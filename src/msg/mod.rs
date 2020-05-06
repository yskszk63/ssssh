use bytes::{Buf, Bytes};

use crate::pack::NameList;
use crate::pack::{Pack, Put, Unpack, UnpackError};

pub(crate) mod channel_close;
pub(crate) mod channel_data;
pub(crate) mod channel_eof;
pub(crate) mod channel_extended_data;
pub(crate) mod channel_failure;
pub(crate) mod channel_open;
pub(crate) mod channel_open_confirmation;
pub(crate) mod channel_open_failure;
pub(crate) mod channel_request;
pub(crate) mod channel_success;
pub(crate) mod channel_window_adjust;
pub(crate) mod debug;
pub(crate) mod disconnect;
pub(crate) mod global_request;
pub(crate) mod ignore;
pub(crate) mod kex_ecdh_init;
pub(crate) mod kex_ecdh_reply;
pub(crate) mod kexinit;
pub(crate) mod new_keys;
pub(crate) mod request_failure;
pub(crate) mod request_success;
pub(crate) mod service_accept;
pub(crate) mod service_request;
pub(crate) mod unimplemented;
pub(crate) mod unknown;
pub(crate) mod userauth_banner;
pub(crate) mod userauth_failure;
pub(crate) mod userauth_passwd_changereq;
pub(crate) mod userauth_request;
pub(crate) mod userauth_success;

trait MsgItem: Pack + Unpack + Into<Msg> {
    const ID: u8;

    fn pack_with_id<P: Put>(&self, buf: &mut P) {
        Self::ID.pack(buf);
        self.pack(buf);
    }
}

macro_rules! Msg {
    (
        $($name:ident ( $type:path ), )+
    ) => {
        #[derive(Debug)]
        pub(crate) enum Msg {
            $($name($type),)+
            Unknown(u8, unknown::Unknown),
        }

        impl Pack for Msg {
            fn pack<P: Put>(&self, buf: &mut P) {
                match self {
                    $(Self::$name(item) => item.pack_with_id(buf),)+
                    Self::Unknown(id, item) => {
                        id.pack(buf);
                        item.pack(buf);
                    }
                }
            }
        }

        impl Unpack for Msg {
            fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
                let result = match u8::unpack(buf)? {
                    $(<$type as MsgItem>::ID => <$type as Unpack>::unpack(buf)?.into(),)+
                    v => Self::Unknown(v, Unpack::unpack(buf)?),
                };
                Ok(result)
            }
        }
    }
}

Msg! {
    Disconnect(disconnect::Disconnect),
    Ignore(ignore::Ignore),
    Unimplemented(unimplemented::Unimplemented),
    Debug(debug::Debug),
    ServiceRequest(service_request::ServiceRequest),
    ServiceAccept(service_accept::ServiceAccept),
    Kexinit(kexinit::BoxKexinit),
    NewKeys(new_keys::NewKeys),
    KexEcdhInit(kex_ecdh_init::KexEcdhInit),
    KexEcdhReply(kex_ecdh_reply::KexEcdhReply),
    UserauthRequest(userauth_request::UserauthRequest),
    UserauthFailure(userauth_failure::UserauthFailure),
    UserauthSuccess(userauth_success::UserauthSuccess),
    UserauthBanner(userauth_banner::UserauthBanner),
    UserauthPasswdChangereq(userauth_passwd_changereq::UserauthPasswdChangereq),
    GlobalRequest(global_request::GlobalRequest),
    RequestSuccess(request_success::RequestSuccess),
    RequestFailure(request_failure::RequestFailure),
    ChannelOpen(channel_open::ChannelOpen),
    ChannelOpenConfirmation(channel_open_confirmation::ChannelOpenConfirmation),
    ChannelOpenFailure(channel_open_failure::ChannelOpenFailure),
    ChannelWindowAdjust(channel_window_adjust::ChannelWindowAdjust),
    ChannelData(channel_data::ChannelData),
    ChannelExtendedData(channel_extended_data::ChannelExtendedData),
    ChannelEof(channel_eof::ChannelEof),
    ChannelClose(channel_close::ChannelClose),
    ChannelRequest(channel_request::ChannelRequest),
    ChannelSuccess(channel_success::ChannelSuccess),
    ChannelFailure(channel_failure::ChannelFailure),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<Msg>();
    }
}
