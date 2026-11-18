//! Argon2id 密钥派生（RFC 9106）。参数全部来自文件头并参与 AAD 认证。

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::{KdfParams, KEY_LEN, SALT_LEN};

/// 派生缓冲区大小上限。
pub type Key = Zeroizing<[u8; KEY_LEN]>;

/// 由用户密码 + 盐 + 参数派生 32 字节主密钥。
///
/// 同一组输入在任何平台（Windows / Android / 第三方 libsodium、argon2
/// 参考实现）上必须得到相同输出，这是跨平台解密的唯一前提。
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Key> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    params.validate()?;

    let argon_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| Error::BadKdfParams(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| Error::BadKdfParams(e.to_string()))?;
    Ok(key)
}

/// 粗略的密码强度评估，仅供 UI 提示，不做解密判断。
///
/// 返回 0..=4：0 为空或极弱，4 为强。评估维度：长度、字符类别、重复与序列。
pub fn password_strength(password: &str) -> u8 {
    if password.is_empty() {
        return 0;
    }
    let chars: Vec<char> = password.chars().collect();
    let len = chars.len();
    let mut classes = 0u8;
    let has_lower = chars.iter().any(|c| c.is_ascii_lowercase());
    let has_upper = chars.iter().any(|c| c.is_ascii_uppercase());
    let has_digit = chars.iter().any(|c| c.is_ascii_digit());
    let has_symbol = chars.iter().any(|c| !c.is_alphanumeric() && !c.is_whitespace());
    let has_cjk = chars.iter().any(|c| ('\u{4e00}'..='\u{9fff}').contains(c));
    for flag in [has_lower, has_upper, has_digit, has_symbol, has_cjk] {
        if flag {
            classes += 1;
        }
    }

    // 重复字符与常见弱口令扣分
    let mut penalties = 0i32;
    let mut max_run = 1;
    let mut run = 1;
    for w in chars.windows(2) {
        if w[0] == w[1] {
            run += 1;
            max_run = max_run.max(run);
        } else {
            run = 1;
        }
    }
    if max_run >= 3 {
        penalties += 1;
    }
    if is_common_password(password) {
        penalties += 3;
    }

    let mut score: i32 = match len {
        0..=5 => 0,
        6..=7 => 1,
        8..=11 => 2,
        12..=15 => 3,
        _ => 4,
    };
    if classes >= 3 && len >= 8 {
        score += 1;
    }
    if classes <= 1 && len < 12 {
        score -= 1;
    }
    score -= penalties;
    score.clamp(0, 4) as u8
}

fn is_common_password(p: &str) -> bool {
    const COMMON: &[&str] = &[
        "123456", "12345678", "123456789", "password", "qwerty", "abc123", "111111",
        "iloveyou", "admin", "letmein", "welcome", "monkey", "dragon", "000000",
        "a123456", "123123", "888888", "666666", "qwerty123", "1qaz2wsx", "woaini",
    ];
    let lower = p.to_ascii_lowercase();
    COMMON.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 固定参数下的 KDF 输出必须与第三方实现一致（见 vectors/kdf_vector.json）。
    #[test]
    fn kdf_matches_reference_vector() {
        let salt = [0u8; SALT_LEN];
        let params = KdfParams { m_cost_kib: 65_536, t_cost: 3, p_cost: 4 };
        let key = derive_key(b"password", &salt, &params).unwrap();
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "592555a93064d6ac4a58d740c0ac9c8eda33b2d4a916b88efd88ea9d6ab65cc2");
    }

    #[test]
    fn kdf_is_deterministic_and_salt_sensitive() {
        let params = KdfParams::mobile();
        let k1 = derive_key(b"pw", &[1u8; SALT_LEN], &params).unwrap();
        let k2 = derive_key(b"pw", &[1u8; SALT_LEN], &params).unwrap();
        let k3 = derive_key(b"pw", &[2u8; SALT_LEN], &params).unwrap();
        assert_eq!(*k1, *k2);
        assert_ne!(*k1, *k3);
    }

    #[test]
    fn empty_password_rejected() {
        assert!(matches!(
            derive_key(b"", &[0u8; SALT_LEN], &KdfParams::mobile()),
            Err(Error::EmptyPassword)
        ));
    }

    #[test]
    fn oversized_params_rejected_before_hashing() {
        let bad = KdfParams { m_cost_kib: 4 * 1024 * 1024, t_cost: 3, p_cost: 1 };
        assert!(matches!(
            derive_key(b"pw", &[0u8; SALT_LEN], &bad),
            Err(Error::HeaderParamOutOfRange(_))
        ));
    }

    #[test]
    fn strength_scores() {
        assert_eq!(password_strength(""), 0);
        assert_eq!(password_strength("123456"), 0);
        assert!(password_strength("Tr0ub4dor&3xK") >= 3);
    }
}
