use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::BufMut;
use std::io::Cursor;
use std::net::UdpSocket;

#[derive(Default, Debug, Clone)]
struct DnsMessage {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsAnswer>,
}
impl DnsMessage {
    fn new(header: DnsHeader, questions: Vec<DnsQuestion>, answers: Vec<DnsAnswer>) -> Self {
        Self {
            header,
            questions,
            answers,
        }
    }
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(38);

        bytes.extend(self.header.to_be_bytes());
        bytes.extend(self.questions.iter().flat_map(|q| q.to_be_bytes().unwrap()));
        bytes.extend(self.answers.iter().flat_map(|a| a.to_be_bytes().unwrap()));

        bytes
    }
    fn read(&mut self, buf: &mut Cursor<&[u8]>) -> Result<()> {
        self.header.read(buf)?;
        self.questions.iter_mut().try_for_each(|q| q.read(buf))?;
        self.answers
            .iter_mut()
            .enumerate()
            .try_for_each(|(i, a)| {a.name = self.questions[i].name.clone(); a.read(buf)})?;
        Ok(())
    }
}

#[derive(Default, Debug, Clone, Copy)]
enum ResponseCode {
    #[default]
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}
impl From<u8> for ResponseCode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            _ => panic!("Invalid value"),
        }
    }
}

#[repr(C, packed)]
#[derive(Default, Debug, Clone, Copy)]
struct DnsHeader {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: bool,
    rcode: ResponseCode,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}
impl DnsHeader {
    fn new(
        id: u16,
        qr: bool,
        opcode: u8,
        aa: bool,
        tc: bool,
        rd: bool,
        ra: bool,
        z: bool,
        rcode: ResponseCode,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
    ) -> Self {
        Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);

        bytes.put_u16(self.id);
        bytes.put_u8(
            ((self.qr as u8) << 7u8)
                | (self.opcode << 3u8)
                | ((self.aa as u8) << 2u8)
                | ((self.tc as u8) << 1u8)
                | (self.rd as u8),
        );
        bytes.put_u8(
            ((self.ra as u8) << 7u8) | ((self.z as u8) << 4u8) | ((self.rcode as u8) << 7u8),
        );
        bytes.put_u16(self.qdcount);
        bytes.put_u16(self.ancount);
        bytes.put_u16(self.nscount);
        bytes.put_u16(self.arcount);

        bytes
    }
    fn read(&mut self, buf: &mut Cursor<&[u8]>) -> Result<()> {
        self.id = buf.read_u16::<BigEndian>()?;

        let flag = buf.read_u8()?;
        self.qr = true;
        self.opcode = (flag & 0b0111_0000) >> 3;
        self.aa = false;
        self.tc = false;
        self.rd = (flag & 0b1) > 0;
        self.ra = false;
        self.z = false;
        self.rcode = if self.opcode == 0 {
            ResponseCode::NoError
        } else {
            ResponseCode::NotImplemented
        };

        self.qdcount = 1;
        self.ancount = 1;
        self.nscount = 0;
        self.arcount = 0;
        Ok(())
    }
}

#[derive(Default, Debug, Clone, Copy)]
enum RecordType {
    #[default]
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
}
impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::NS,
            3 => Self::MD,
            4 => Self::MF,
            5 => Self::CNAME,
            6 => Self::SOA,
            7 => Self::MB,
            8 => Self::MG,
            9 => Self::MR,
            10 => Self::NULL,
            11 => Self::WKS,
            12 => Self::PTR,
            13 => Self::HINFO,
            14 => Self::MINFO,
            15 => Self::MX,
            16 => Self::TXT,
            _ => panic!("Invalid value"),
        }
    }
}
#[derive(Default, Debug, Clone, Copy)]
enum RecordClass {
    #[default]
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}
impl From<u16> for RecordClass {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            _ => panic!("Invalid value"),
        }
    }
}

#[derive(Default, Debug, Clone)]
struct DnsQuestion {
    name: String,
    r#type: RecordType,
    class: RecordClass,
}
impl DnsQuestion {
    fn new(name: String, r#type: RecordType, class: RecordClass) -> Self {
        Self {
            name,
            r#type,
            class,
        }
    }
    fn to_be_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(10);
        let (l1, l2) = self
            .name
            .rsplit_once('.')
            .ok_or_else(|| anyhow!("Invalid label"))?;
        if l1.len() > 255 || l2.len() > 255 {
            return Err(anyhow!("Label is too big"));
        }

        bytes.extend((l1.len() as u8).to_be_bytes());
        bytes.extend(l1.as_bytes());
        bytes.extend((l2.len() as u8).to_be_bytes());
        bytes.extend(l2.as_bytes());
        bytes.put_u8(0);
        bytes.extend((self.r#type as u16).to_be_bytes());
        bytes.extend((self.class as u16).to_be_bytes());

        Ok(bytes)
    }
    fn read(&mut self, buf: &mut Cursor<&[u8]>) -> Result<()> {
        let mut name = Vec::new();
        loop {
            let len = buf.read_u8().unwrap_or(0);
            if len == 0 {
                break;
            }
            for _ in 0..len {
                name.push(buf.read_u8().unwrap_or(0));
            }
            buf.set_position(buf.position() + len as u64);
            name.push(0);
        }
        self.r#type = RecordType::A;
        self.class = RecordClass::IN;

        Ok(())
    }
}

#[derive(Default, Debug, Clone)]
struct DnsAnswer {
    name: String,
    r#type: RecordType,
    class: RecordClass,
    ttl: u32,
    length: u16,
    data: Vec<u8>,
}
impl DnsAnswer {
    fn new(
        name: String,
        r#type: RecordType,
        class: RecordClass,
        ttl: u32,
        length: u16,
        data: Vec<u8>,
    ) -> Self {
        Self {
            name,
            r#type,
            class,
            ttl,
            length,
            data,
        }
    }
    fn to_be_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(16);
        let (l1, l2) = self
            .name
            .rsplit_once('.')
            .ok_or_else(|| anyhow!("Invalid label"))?;
        if l1.len() > 255 || l2.len() > 255 {
            panic!();
        }

        bytes.extend((l1.len() as u8).to_be_bytes());
        bytes.extend(l1.as_bytes());
        bytes.extend((l2.len() as u8).to_be_bytes());
        bytes.extend(l2.as_bytes());
        bytes.put_u8(0);
        bytes.extend((self.r#type as u16).to_be_bytes());
        bytes.extend((self.class as u16).to_be_bytes());
        bytes.extend(self.ttl.to_be_bytes());
        bytes.extend(self.length.to_be_bytes());
        bytes.extend(self.data.as_slice());

        Ok(bytes)
    }
    fn read(&mut self, buf: &mut Cursor<&[u8]>) -> Result<()> {
        
        self.r#type = RecordType::A;
        self.class = RecordClass::IN;
        self.ttl = 60;
        self.length = 4;
        self.data = vec![8,8,8,8];

        Ok(())
    }
}

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0u8; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let mut cursor = Cursor::new(&buf[0..size]);

                let header = DnsHeader::default();
                let questions = DnsQuestion::default();
                let answers = DnsAnswer::default();

                let mut response = DnsMessage::new(header, vec![questions], vec![answers]);
                response.read(&mut cursor).unwrap();

                udp_socket
                    .send_to(&response.to_be_bytes(), source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
