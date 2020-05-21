use std::fmt;

use bytes::{Buf, Bytes, BytesMut};

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
pub(crate) mod kex_dh_gex_group;
pub(crate) mod kex_dh_gex_init;
pub(crate) mod kex_dh_gex_reply;
pub(crate) mod kex_dh_gex_request;
pub(crate) mod kex_dh_gex_request_old;
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

trait MsgItem<M = Msg>: Pack + Unpack + Into<M> {
    const ID: u8;

    fn pack_with_id<P: Put>(&self, buf: &mut P) {
        Self::ID.pack(buf);
        self.pack(buf);
    }
}

pub(crate) trait ContextualMsg: Into<Msg> + Pack + Unpack + fmt::Debug {}

macro_rules! Msg {
    (
        $ty:ident {
            $($name:ident ( $type:path ), )+
        }
    ) => {
        #[derive(Debug)]
        pub(crate) enum $ty {
            $($name($type),)+
            Unknown(u8, unknown::Unknown),
        }

        impl $ty {
            #[allow(dead_code)]
            fn into_unknown(self) -> Msg {
                let id = match &self {
                    $(Self::$name(..) => <$type as MsgItem<$ty>>::ID,)+
                    Self::Unknown(id, ..) => *id,
                };
                let mut buf = BytesMut::new();
                match self {
                    $(Self::$name(item) => item.pack(&mut buf),)+
                    Self::Unknown(_, item) => item.pack(&mut buf),
                }
                Msg::Unknown(id, unknown::Unknown::new(buf.freeze()))
            }
        }

        impl Pack for $ty {
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

        impl Unpack for $ty {
            fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
                let result = match u8::unpack(buf)? {
                    $(<$type as MsgItem<$ty>>::ID => <$type as Unpack>::unpack(buf)?.into(),)+
                    v => Self::Unknown(v, Unpack::unpack(buf)?),
                };
                Ok(result)
            }
        }
    }
}

Msg! {
    Msg {
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
}

Msg! {
    GexMsg {
        KexDhGexRequestOld(kex_dh_gex_request_old::KexDhGexRequestOld),
        KexDhGexRequest(kex_dh_gex_request::KexDhGexRequest),
        KexDhGexGroup(kex_dh_gex_group::KexDhGexGroup),
        KexDhGexInit(kex_dh_gex_init::KexDhGexInit),
        KexDhGexReply(kex_dh_gex_reply::KexDhGexReply),
    }
}

impl ContextualMsg for GexMsg {}

impl From<GexMsg> for Msg {
    fn from(v: GexMsg) -> Self {
        v.into_unknown()
    }
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
