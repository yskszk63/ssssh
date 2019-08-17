use std::convert::TryFrom;

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct UnknownMessageId(u8);

impl UnknownMessageId {
    pub fn id(&self) -> u8 {
        self.0
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum MessageId {
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    ServiceRequest = 5,
    ServiceAccept = 6,
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
            1 => Self::Disconnect,
            2 => Self::Ignore,
            3 => Self::Unimplemented,
            4 => Self::Debug,
            5 => Self::ServiceRequest,
            6 => Self::ServiceAccept,
            20 => Self::Kexinit,
            21 => Self::Newkeys,
            30 => Self::KexEcdhInit,
            31 => Self::KexEcdhReply,
            50 => Self::UserauthRequest,
            51 => Self::UserauthFailure,
            52 => Self::UserauthSuccess,
            53 => Self::UserauthBanner,
            80 => Self::GlobalRequest,
            81 => Self::RequestSuccess,
            82 => Self::RequestFailure,
            90 => Self::ChannelOpen,
            91 => Self::ChannelOpenConfirmation,
            92 => Self::ChannelOpenFailure,
            93 => Self::ChannelWindowAdjust,
            94 => Self::ChannelData,
            95 => Self::ChannelExtendedData,
            96 => Self::ChannelEof,
            97 => Self::ChannelClose,
            98 => Self::ChannelRequest,
            99 => Self::ChannelSuccess,
            100 => Self::ChannelFailure,
            e => return Err(UnknownMessageId(e)),
        })
    }
}
