//! OpenSSH `authorized_keys` parser.
use std::iter::IntoIterator;
use std::str::FromStr;

use authorized_keys::openssh::v2::{KeysFile, KeysFileLine};
use tokio::io::{self, AsyncRead, AsyncReadExt};

use crate::PublicKey;

/// OpenSSH `authorized_keys` parse error.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("{0}")]
    Any(String),
}

/// represent `authorized_keys` line.
#[derive(Debug)]
pub struct AuthorizedKey {
    options: Vec<(String, Option<String>)>,
    key_type: String,
    publickey: PublicKey,
    comment: String,
}

impl AuthorizedKey {
    pub fn options(&self) -> &[(String, Option<String>)] {
        &self.options
    }

    pub fn key_type(&self) -> &str {
        &self.key_type
    }

    pub fn publickey(&self) -> &PublicKey {
        &self.publickey
    }

    pub fn comment(&self) -> &str {
        &self.comment
    }
}

/// OpenSSH represent `authorized_keys`.
#[derive(Debug)]
pub struct AuthorizedKeys(Vec<AuthorizedKey>);

impl AuthorizedKeys {
    /// parse OpenSSH `authorized_keys`.
    ///
    /// # Example
    ///
    /// ```
    /// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
    /// use ssssh::authorized_keys::AuthorizedKeys;
    /// let authorized_keys_file = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBGr/hiKoT+ED6BGl0rYM8Ai96O/2lbnGM++zAbz578V";
    /// AuthorizedKeys::parse(&authorized_keys_file[..]).await.unwrap();
    /// # });
    /// ```
    pub async fn parse<R>(mut reader: R) -> Result<Self, ParseError>
    where
        R: AsyncRead + Unpin,
    {
        let mut content = String::new();
        reader.read_to_string(&mut content).await?;
        let keysfile = KeysFile::from_str(&content).map_err(|e| ParseError::Any(e))?;

        let mut keys = vec![];
        for line in keysfile {
            if let KeysFileLine::Key(line) = line {
                match line.key.encoded_key.parse() {
                    Ok(publickey) => keys.push(AuthorizedKey {
                        options: line.options,
                        key_type: line.key.key_type.to_string(),
                        publickey,
                        comment: line.comments,
                    }),
                    Err(err) => {
                        // skip unparsable key.
                        log::warn!("failed to parse key {:?}: {}", line, err)
                    }
                }
            }
        }
        Ok(Self(keys))
    }
}

impl IntoIterator for AuthorizedKeys {
    type Item = AuthorizedKey;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test() {
        let authorized_keys = br#"# Comments allowed at start of line
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMxtwvOyA4hdYDT6WrW/Q0xe9KHpJf1O+qclqpVV9iyyHPdUSOVSq9Yz3ZbOt4ZdYRXhudc/z7xq4Gyy1ERuXwdzD5asoKR3wD/I97slCUu56X3JE8NCyk0vKezTwVhWHv3S+RGazj4cX3PUHbm2p7bopa6belb9//F9Ttz51+Pkmk6WXEsjtjeiJKVMjlr9GwqrsOKtNalIlCVoJRq2lVN2SSJyMtRpHZFJ+8ox2BMvkqvAHTGOnFmRiJXK8fCH/hEFv8UV5hkGe10gTBL8/5/wnazk6cos1cuBhGDJxKh+Sb7k40Q3KhkiCtLWxmXZC9Z33xJyEf/oFrDm/K+MxA7QfkSY8iL5017XUU0rBSZSLXah6PVfhdrqhyGbJImAqI1Xjv++9lGzqtP9D2SAwEj7IQLOtgc4WifASuTY2MGmFkapS8YJPCTE2O2lwWoTNIi0Lpo2JfwZzKPvE/7hF2V3c/BCACoGjsQzBdNjJ/DiyNjrNvsv7URpWQikkFuTs= user@example.net
from="*.sales.example.net,!pc.sales.example.net" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCiRkXnPlFS9mddGf9OOZ8h9M1iLmvzoaDARKQmp+zPXC3qCsi6teFna5+AAibTbUhlzdgSy+t7gK19XDS5aelMnbAbFXu+hrwDxncGFt9s/WtmTibbSEU2bvlvSjgfp/Ifmn9xqTT/ky9+z77qsTVpaJUTNxPDL9OxPN40Fiao9L6D6IxHwx1wmVfA2rAuWTpJNLlOIb/1ZrpZfEeuUPKq1h0ozM0ptN28nesONdYa87qoeQMFsyoLDrayrhM3X0ypO1OAVcMavwXEcp/meNQIyU/DUkCKjkinrxQM186bMjgmHtYyzpqFIrxEMRjPFMWSiP4w+kIPiJObYQfNL1DJJBhnmm9xDwS7aT7WJ1XZn5Qs1gXT4Ck4tNWxQAKzbTEgIXs64F9tgaflBhibdCU3LtsQ0jqTITTtXTZtndJ7lNrMxC88LysuEJzsQebv0mVhOjHRmmPB4/7NIfuOjckqvgEUx0tTZo3vL5yXGBGFNGR9vNbHX9Hos6hTNsCxQv0= john@example.net
command="dump /home",no-pty,no-port-forwarding ssh-dss AAAAB3NzaC1kc3MAAACBAOKN80C2R7MgFr2PgayAWLR8x8M49eo2aZODh6esDaf/alKT0Hn5Ioo/1YtU+hLGbcQM8xo1PFErlFwV4pPQv2fn6PQjYHMrz8n9yx9hT/X3bNTT+8qFJaP8Q/8s70JokL91uBkJalstg2qKRvIVjoLG8lMqZBqfPwEezT5Ie55lAAAAFQDHGJfmKm+L3Tz4TU+Y4Xgd+2/cYQAAAIAxxR6QAn3A8Om+ye03+Qt16QgdwfpzMt18X4BVIA94fjiRQvDGyyH8PK6evPf6lwxTC/s974/tI4xoYsp6ccxMuFKhtJ/lbgS+a1cAK0dRv4FijbCtGR954VXWYBfp0AqLNl/do5byywT0cZyUdM+WUa4Mo0OwpKAJ6UmmVCAVbwAAAIB/dQx679qQEcgx185mZgvsYpa2c6Nm9HhxX1WHE+23RBYS2HM5DlJErjNRhSoIUMg0/9MrYM2YMDjjCxepzIbhE/r+UlT7WWID5id3CELte33zJ/TrDFu2D2hSSASCCCouJkKUhvoUR1ngvPVLkJR21Otc3B2QcTx+jj8zlTtL8Q== example.net
permitopen="192.0.2.1:80",permitopen="192.0.2.2:25" ssh-dss AAAAB3NzaC1kc3MAAACBAOx6RIBrcQY4dMShoPkcbjdf9CBHDxeYtauW3f5nbbd+7IolKOps/j665BPybrqnf9MkjnDXF2z02/ZTVLNBmfoFTOv5Y5C/P0lB2jK1PRRTUBDVZxU+DdwL1zA2FNCk5fqEE7Aq8AttVNDWxWrseAW7fWxQc8M0EyyxQRtOVrjdAAAAFQCfPbZPd2R0OFmX5HDq93wa26kXZwAAAIEA4UOR66abDGm3MFUPISbfFqSMB/DmAczQiDhnyyo6/fin2lb9phKo5pkPkPFkBz3/SJfFjdIe1dDO5/yTLymx+YSNy58nbVqCmloa3zjdzdTdM6w+ikP1V3BRnEHpOwRs39794rhHA+6MVmUFX4y/9Pjrmp2XUk56kotW4EpvYSYAAACAVa3FHcd8b2EGLlzMOAQ1sYBkYZ59W0BdazTTMKTeK3kc5awVISKXMF08YGiR7GTuZvi62eimb6rRF15H79oLM4gVUd0hSh0KQ60ysIzqgDJVNfAgN+OQLPXFc40y7P+WuTG7SH8fhGkJz9/DUCAqoYQZ36NKsLi2467aqm4LOd8=
tunnel="0",command="sh /etc/netstart tun0" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDtIK4bgK4vBxBBrMVsliyxedisxUQYjfKIUMivOXy+skqwt1bVmkWxA1+3WgHJjTACalabc8+JBEdfi4TD1ZvlV05krrK3ZV0v3FFyW46oHLImtOrtD5wiMo6Ze0DQKVwgRuDjKBVersH5PNbwH6oWutGQY8jgajLEAtehpKWo+I/eVBmbWmqWUwBjW5i2OfLgrkihwpQ1RgaT2o9lkRwmNSmyZdPrU29rGIlkOoukEssLVDap/lX2G1GOK/lgT4F9HZo3zbFUFq1VG9JrzhrwdlIj+MU5tWimqOUUkrDZ7Vx43OYD0OEfZVaL0fRnWPqzXU6cspGseMdeC5NWljmkPmSB2K3gZjvS5EnsZepSQ0d8N+rEDA5goQTJaTNssV2Dh7WxUvUjJEfLajTMLNRC1guSKA5rWx3lK06pda9GVV6sW+YATIkSpvNRCFKi8ys9D1hCxjnc4B5TeVGYoyD4AwcrclEoaCj5E8QoyZrJtZBmXbCXMqzCIKs/t1LAag8= jane@example.net
restrict,command="uptime" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7gglwOIUjiUA/iI00Qs84HZoA3QlPvFAAMorBUPM8sesxKA0HQ1JChMvO14+mx4gQ8MIk9bFCp5ukemnoWizwYvbM3Os3+Ns/0T2Vpxt9Bvb/fPOuwNrvRQQJ6LOUqPgt3SH1GvXSocyUYTU6Tip2K9af8FQPId4QNB3MLTycMlSEYV1Yx0OoT3DFOdOMUur7Z515JgUlvUWIY//ZQrdMjYkn0qXG7X4nBycIIWRQ53kV9MmDO+Z4NbUQEN5ex140x1wwYnSjxcMi1408hz8X1OC4Iz44MGceghUDxYVv88Y8iJZAkSGbgAwkQljD1uczrD8BD25IO9a/M9FpNiBT5ETkSXchrlGNcqP94kJRM/Wrtrw+2igVwcvbi1s4Jc4K0Rea6AEhlvOPOVg4Edldt1lIn4mp7XFEEW6ldQAEpqUADrgllxTN+bV9U2yUZhMzGRBfR7Cc/lHhWSgVF/8zd4tkPky56jtDzT833j3QPpUqPQ6kNTGwzTOu8ap4COE= user@example.net
restrict,pty,command="nethack" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwgKJ9qbRMmhYhjGhRRKHHVF8h7IOzOuB1B/XiiexfIPVK9kRBKKMpKmz7lGD1R2TQ2yIDgTjk0Z0xKKtrlHvkLH/78YIV5n3jT3IGHz9WsQBWMg8woFLQQj3eTcWjsRuOrIBOBRBky1h8/mXVxkY1dJZorajJB6svpNNO5Hfm9Ab8INyWPZY3b/qccA1RVChekzj6DnE6VAwcv1xJ3bT8NoCa5q+E1EAGiS/CZH0HzCceqYveP+Z4YmgOTJYufAr9WVKkXydsxKNpKsK3//+yT6MM907RZQonmN0/3+qAjvqi0dUoHCttbuNeNeXRGlcGfWM8u9Kxr5WSCVu2620ETdf6V4IVKZRwUBMclr8oZEiPWOEoiJ4nGjczuIbnKA/U4eyotoTCQrSXNlPp13jvak8Xfb8YzpFPpSDKZ1aD491XNZ2aeUTKVpTfqDiIJ8xSZWCN7D2nEZILcOfTUHnQ0q3FXO3YKkPPotbnk288Tlo8znZwl6OtV7lXg+Ucjkc= user@example.net"#;

        let authorized_keys = AuthorizedKeys::parse(&authorized_keys[..]).await.unwrap();

        let expects = vec![
            PublicKey::from_str("AAAAB3NzaC1yc2EAAAADAQABAAABgQDMxtwvOyA4hdYDT6WrW/Q0xe9KHpJf1O+qclqpVV9iyyHPdUSOVSq9Yz3ZbOt4ZdYRXhudc/z7xq4Gyy1ERuXwdzD5asoKR3wD/I97slCUu56X3JE8NCyk0vKezTwVhWHv3S+RGazj4cX3PUHbm2p7bopa6belb9//F9Ttz51+Pkmk6WXEsjtjeiJKVMjlr9GwqrsOKtNalIlCVoJRq2lVN2SSJyMtRpHZFJ+8ox2BMvkqvAHTGOnFmRiJXK8fCH/hEFv8UV5hkGe10gTBL8/5/wnazk6cos1cuBhGDJxKh+Sb7k40Q3KhkiCtLWxmXZC9Z33xJyEf/oFrDm/K+MxA7QfkSY8iL5017XUU0rBSZSLXah6PVfhdrqhyGbJImAqI1Xjv++9lGzqtP9D2SAwEj7IQLOtgc4WifASuTY2MGmFkapS8YJPCTE2O2lwWoTNIi0Lpo2JfwZzKPvE/7hF2V3c/BCACoGjsQzBdNjJ/DiyNjrNvsv7URpWQikkFuTs=").unwrap(),
            PublicKey::from_str("AAAAB3NzaC1yc2EAAAADAQABAAABgQCiRkXnPlFS9mddGf9OOZ8h9M1iLmvzoaDARKQmp+zPXC3qCsi6teFna5+AAibTbUhlzdgSy+t7gK19XDS5aelMnbAbFXu+hrwDxncGFt9s/WtmTibbSEU2bvlvSjgfp/Ifmn9xqTT/ky9+z77qsTVpaJUTNxPDL9OxPN40Fiao9L6D6IxHwx1wmVfA2rAuWTpJNLlOIb/1ZrpZfEeuUPKq1h0ozM0ptN28nesONdYa87qoeQMFsyoLDrayrhM3X0ypO1OAVcMavwXEcp/meNQIyU/DUkCKjkinrxQM186bMjgmHtYyzpqFIrxEMRjPFMWSiP4w+kIPiJObYQfNL1DJJBhnmm9xDwS7aT7WJ1XZn5Qs1gXT4Ck4tNWxQAKzbTEgIXs64F9tgaflBhibdCU3LtsQ0jqTITTtXTZtndJ7lNrMxC88LysuEJzsQebv0mVhOjHRmmPB4/7NIfuOjckqvgEUx0tTZo3vL5yXGBGFNGR9vNbHX9Hos6hTNsCxQv0=").unwrap(),
            PublicKey::from_str("AAAAB3NzaC1kc3MAAACBAOKN80C2R7MgFr2PgayAWLR8x8M49eo2aZODh6esDaf/alKT0Hn5Ioo/1YtU+hLGbcQM8xo1PFErlFwV4pPQv2fn6PQjYHMrz8n9yx9hT/X3bNTT+8qFJaP8Q/8s70JokL91uBkJalstg2qKRvIVjoLG8lMqZBqfPwEezT5Ie55lAAAAFQDHGJfmKm+L3Tz4TU+Y4Xgd+2/cYQAAAIAxxR6QAn3A8Om+ye03+Qt16QgdwfpzMt18X4BVIA94fjiRQvDGyyH8PK6evPf6lwxTC/s974/tI4xoYsp6ccxMuFKhtJ/lbgS+a1cAK0dRv4FijbCtGR954VXWYBfp0AqLNl/do5byywT0cZyUdM+WUa4Mo0OwpKAJ6UmmVCAVbwAAAIB/dQx679qQEcgx185mZgvsYpa2c6Nm9HhxX1WHE+23RBYS2HM5DlJErjNRhSoIUMg0/9MrYM2YMDjjCxepzIbhE/r+UlT7WWID5id3CELte33zJ/TrDFu2D2hSSASCCCouJkKUhvoUR1ngvPVLkJR21Otc3B2QcTx+jj8zlTtL8Q==").unwrap(),
            PublicKey::from_str("AAAAB3NzaC1kc3MAAACBAOx6RIBrcQY4dMShoPkcbjdf9CBHDxeYtauW3f5nbbd+7IolKOps/j665BPybrqnf9MkjnDXF2z02/ZTVLNBmfoFTOv5Y5C/P0lB2jK1PRRTUBDVZxU+DdwL1zA2FNCk5fqEE7Aq8AttVNDWxWrseAW7fWxQc8M0EyyxQRtOVrjdAAAAFQCfPbZPd2R0OFmX5HDq93wa26kXZwAAAIEA4UOR66abDGm3MFUPISbfFqSMB/DmAczQiDhnyyo6/fin2lb9phKo5pkPkPFkBz3/SJfFjdIe1dDO5/yTLymx+YSNy58nbVqCmloa3zjdzdTdM6w+ikP1V3BRnEHpOwRs39794rhHA+6MVmUFX4y/9Pjrmp2XUk56kotW4EpvYSYAAACAVa3FHcd8b2EGLlzMOAQ1sYBkYZ59W0BdazTTMKTeK3kc5awVISKXMF08YGiR7GTuZvi62eimb6rRF15H79oLM4gVUd0hSh0KQ60ysIzqgDJVNfAgN+OQLPXFc40y7P+WuTG7SH8fhGkJz9/DUCAqoYQZ36NKsLi2467aqm4LOd8=").unwrap(),
            PublicKey::from_str("AAAAB3NzaC1yc2EAAAADAQABAAABgQDtIK4bgK4vBxBBrMVsliyxedisxUQYjfKIUMivOXy+skqwt1bVmkWxA1+3WgHJjTACalabc8+JBEdfi4TD1ZvlV05krrK3ZV0v3FFyW46oHLImtOrtD5wiMo6Ze0DQKVwgRuDjKBVersH5PNbwH6oWutGQY8jgajLEAtehpKWo+I/eVBmbWmqWUwBjW5i2OfLgrkihwpQ1RgaT2o9lkRwmNSmyZdPrU29rGIlkOoukEssLVDap/lX2G1GOK/lgT4F9HZo3zbFUFq1VG9JrzhrwdlIj+MU5tWimqOUUkrDZ7Vx43OYD0OEfZVaL0fRnWPqzXU6cspGseMdeC5NWljmkPmSB2K3gZjvS5EnsZepSQ0d8N+rEDA5goQTJaTNssV2Dh7WxUvUjJEfLajTMLNRC1guSKA5rWx3lK06pda9GVV6sW+YATIkSpvNRCFKi8ys9D1hCxjnc4B5TeVGYoyD4AwcrclEoaCj5E8QoyZrJtZBmXbCXMqzCIKs/t1LAag8=").unwrap(),
            PublicKey::from_str("AAAAB3NzaC1yc2EAAAADAQABAAABgQC7gglwOIUjiUA/iI00Qs84HZoA3QlPvFAAMorBUPM8sesxKA0HQ1JChMvO14+mx4gQ8MIk9bFCp5ukemnoWizwYvbM3Os3+Ns/0T2Vpxt9Bvb/fPOuwNrvRQQJ6LOUqPgt3SH1GvXSocyUYTU6Tip2K9af8FQPId4QNB3MLTycMlSEYV1Yx0OoT3DFOdOMUur7Z515JgUlvUWIY//ZQrdMjYkn0qXG7X4nBycIIWRQ53kV9MmDO+Z4NbUQEN5ex140x1wwYnSjxcMi1408hz8X1OC4Iz44MGceghUDxYVv88Y8iJZAkSGbgAwkQljD1uczrD8BD25IO9a/M9FpNiBT5ETkSXchrlGNcqP94kJRM/Wrtrw+2igVwcvbi1s4Jc4K0Rea6AEhlvOPOVg4Edldt1lIn4mp7XFEEW6ldQAEpqUADrgllxTN+bV9U2yUZhMzGRBfR7Cc/lHhWSgVF/8zd4tkPky56jtDzT833j3QPpUqPQ6kNTGwzTOu8ap4COE=").unwrap(),
            PublicKey::from_str("AAAAB3NzaC1yc2EAAAADAQABAAABgQCwgKJ9qbRMmhYhjGhRRKHHVF8h7IOzOuB1B/XiiexfIPVK9kRBKKMpKmz7lGD1R2TQ2yIDgTjk0Z0xKKtrlHvkLH/78YIV5n3jT3IGHz9WsQBWMg8woFLQQj3eTcWjsRuOrIBOBRBky1h8/mXVxkY1dJZorajJB6svpNNO5Hfm9Ab8INyWPZY3b/qccA1RVChekzj6DnE6VAwcv1xJ3bT8NoCa5q+E1EAGiS/CZH0HzCceqYveP+Z4YmgOTJYufAr9WVKkXydsxKNpKsK3//+yT6MM907RZQonmN0/3+qAjvqi0dUoHCttbuNeNeXRGlcGfWM8u9Kxr5WSCVu2620ETdf6V4IVKZRwUBMclr8oZEiPWOEoiJ4nGjczuIbnKA/U4eyotoTCQrSXNlPp13jvak8Xfb8YzpFPpSDKZ1aD491XNZ2aeUTKVpTfqDiIJ8xSZWCN7D2nEZILcOfTUHnQ0q3FXO3YKkPPotbnk288Tlo8znZwl6OtV7lXg+Ucjkc=").unwrap(),
        ];

        let mut authorized_keys = authorized_keys.into_iter();
        for expect in expects {
            let key = authorized_keys.next().unwrap();
            assert_eq!(key.publickey(), &expect);
        }
    }
}
