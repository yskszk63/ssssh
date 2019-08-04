use std::convert::TryFrom;

#[derive(Debug)]
pub struct UnknownMessageId(u8);

impl UnknownMessageId {
    pub fn id(&self) -> u8 {
        self.0
    }
}

#[derive(Debug)]
pub enum MessageId {
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    ServerRequest = 5,
    Accept = 6,
    Kexinit = 20,
    Newkeys = 21,
    KexEcdhInit = 30,
    KexEcdhReply = 31,
    UserauthRequest = 50,
    UserauthFailure = 51,
    UserauthSuccess = 52,
    UserauthBanner = 53,
    GlobalRequest = 80,
    RequestSuccess = 81,
    RequestFailure = 82,
    ChannelOpen = 90,
    ChannelOpenConfirmation = 91,
    ChannelOpenFailure = 92,
    ChannelWindowAdjust = 93,
    ChannelData = 94,
    ChannelExtendedData = 95,
    ChannelEof = 96,
    ChannelClose = 97,
    ChannelRequest = 98,
    ChannelSuccess = 99,
    ChannelFailure = 100,
}

impl TryFrom<u8> for MessageId {
    type Error = UnknownMessageId;

    fn try_from(v: u8) -> Result<Self, UnknownMessageId> {
        Ok(match v {
            1 => MessageId::Disconnect,
            2 => MessageId::Ignore,
            3 => MessageId::Unimplemented,
            4 => MessageId::Debug,
            5 => MessageId::ServerRequest,
            6 => MessageId::Accept,
            20 => MessageId::Kexinit,
            21 => MessageId::Newkeys,
            30 => MessageId::KexEcdhInit,
            31 => MessageId::KexEcdhReply,
            50 => MessageId::UserauthRequest,
            51 => MessageId::UserauthFailure,
            52 => MessageId::UserauthSuccess,
            53 => MessageId::UserauthBanner,
            80 => MessageId::GlobalRequest,
            81 => MessageId::RequestSuccess,
            82 => MessageId::RequestFailure,
            90 => MessageId::ChannelOpen,
            91 => MessageId::ChannelOpenConfirmation,
            92 => MessageId::ChannelOpenFailure,
            93 => MessageId::ChannelWindowAdjust,
            94 => MessageId::ChannelData,
            95 => MessageId::ChannelExtendedData,
            96 => MessageId::ChannelEof,
            97 => MessageId::ChannelClose,
            98 => MessageId::ChannelRequest,
            99 => MessageId::ChannelSuccess,
            100 => MessageId::ChannelFailure,
            e => return Err(UnknownMessageId(e)),
        })
    }
}
