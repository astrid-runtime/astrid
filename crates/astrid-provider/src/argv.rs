//! Structured job argv. Tokens are not a shell line.

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, read_nested,
    require_exact_len, require_zero_padding, take, write_header, write_nested,
};
use crate::error::ProviderError;

/// Maximum bytes in one argv token. Encoding ceiling, not a config knob.
pub const ARG_MAX_BYTES: usize = 64;
/// Maximum argv tokens including the program name. Encoding ceiling, not a config knob.
pub const ARGV_MAX: usize = 8;

/// One structured argument token. Opaque bytes, not a shell word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobArg {
    bytes: [u8; ARG_MAX_BYTES],
    len: u8,
}

impl JobArg {
    /// Exact encoded length, including unused zero padding.
    pub const ENCODED_LEN: usize = 68;

    /// Parse a non-empty token.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::EmptyArg`] or [`ProviderError::ArgTooLong`].
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, ProviderError> {
        if bytes.is_empty() {
            return Err(ProviderError::EmptyArg);
        }
        if bytes.len() > ARG_MAX_BYTES {
            return Err(ProviderError::ArgTooLong);
        }
        let mut token = [0_u8; ARG_MAX_BYTES];
        let slot = token
            .get_mut(..bytes.len())
            .ok_or(ProviderError::ArgTooLong)?;
        slot.copy_from_slice(bytes);
        Ok(Self {
            bytes: token,
            len: u8::try_from(bytes.len()).map_err(|_| ProviderError::ArgTooLong)?,
        })
    }

    /// Token bytes, without padding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

impl DescriptorEncode for JobArg {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        require_exact_len(output, Self::ENCODED_LEN)?;
        output.fill(0);
        write_header(output, ProviderTypeTag::JobArg)?;
        let len_slot = output.get_mut(3).ok_or(ProviderError::InvalidLength)?;
        *len_slot = self.len;
        let used = usize::from(self.len);
        output
            .get_mut(4..)
            .and_then(|rest| rest.get_mut(..used))
            .ok_or(ProviderError::InvalidLength)?
            .copy_from_slice(self.as_bytes());
        Ok(())
    }
}

impl DescriptorDecode for JobArg {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::JobArg)?;
        let (len_bytes, offset) = take(input, 3, 1)?;
        let len = len_bytes[0];
        if len == 0 {
            return Err(ProviderError::EmptyArg);
        }
        if usize::from(len) > ARG_MAX_BYTES {
            return Err(ProviderError::ArgTooLong);
        }
        let (body, _) = take(input, offset, ARG_MAX_BYTES)?;
        let (used, padding) = body.split_at(usize::from(len));
        require_zero_padding(padding)?;
        Self::try_from_bytes(used)
    }
}

/// Bounded structured argv. Index zero is the program name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobArgv {
    args: [Option<JobArg>; ARGV_MAX],
    count: u8,
}

impl JobArgv {
    /// Exact encoded length, including unused zero padding.
    pub const ENCODED_LEN: usize = 548;

    /// Construct argv from tokens. At least the program name is required.
    ///
    /// # Errors
    ///
    /// Rejects empty argv, oversize argv, empty tokens, and oversize tokens.
    pub fn try_from_args(args: &[&[u8]]) -> Result<Self, ProviderError> {
        if args.is_empty() {
            return Err(ProviderError::EmptyArgv);
        }
        if args.len() > ARGV_MAX {
            return Err(ProviderError::ArgvLimit);
        }
        let mut slots = [None; ARGV_MAX];
        for (index, arg) in args.iter().enumerate() {
            let slot = slots.get_mut(index).ok_or(ProviderError::ArgvLimit)?;
            *slot = Some(JobArg::try_from_bytes(arg)?);
        }
        Ok(Self {
            args: slots,
            count: u8::try_from(args.len()).map_err(|_| ProviderError::ArgvLimit)?,
        })
    }

    /// Number of stored tokens.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Whether there are no tokens. Constructors reject empty argv.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate tokens in order, starting with the program name.
    pub fn iter(&self) -> impl Iterator<Item = &JobArg> {
        self.args.iter().take(self.len()).filter_map(Option::as_ref)
    }
}

impl DescriptorEncode for JobArgv {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        require_exact_len(output, Self::ENCODED_LEN)?;
        output.fill(0);
        write_header(output, ProviderTypeTag::JobArgv)?;
        let count_slot = output.get_mut(3).ok_or(ProviderError::InvalidLength)?;
        *count_slot = self.count;
        let mut offset = 4_usize;
        for arg in self.iter() {
            offset = write_nested(output, offset, arg)?;
        }
        Ok(())
    }
}

impl DescriptorDecode for JobArgv {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::JobArgv)?;
        let (count_bytes, mut offset) = take(input, 3, 1)?;
        let count = count_bytes[0];
        if count == 0 {
            return Err(ProviderError::EmptyArgv);
        }
        if usize::from(count) > ARGV_MAX {
            return Err(ProviderError::ArgvLimit);
        }
        let mut args = [None; ARGV_MAX];
        for index in 0..usize::from(count) {
            let (arg, next) = read_nested::<JobArg>(input, offset, JobArg::ENCODED_LEN)?;
            let slot = args.get_mut(index).ok_or(ProviderError::ArgvLimit)?;
            *slot = Some(arg);
            offset = next;
        }
        require_zero_padding(input.get(offset..).ok_or(ProviderError::InvalidLength)?)?;
        Ok(Self { args, count })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_requires_a_program_name_and_rejects_padding_garbage() {
        assert_eq!(JobArgv::try_from_args(&[]), Err(ProviderError::EmptyArgv));
        assert_eq!(JobArg::try_from_bytes(&[]), Err(ProviderError::EmptyArg));
        assert_eq!(
            JobArg::try_from_bytes(&[0; 65]),
            Err(ProviderError::ArgTooLong)
        );
        let argv = JobArgv::try_from_args(&[b"prog", b"-k"]).unwrap();
        let mut encoded = [0_u8; JobArgv::ENCODED_LEN];
        argv.encode_descriptor(&mut encoded).unwrap();
        assert_eq!(JobArgv::decode_descriptor(&encoded), Ok(argv));
        let pad_at = 4_usize
            .checked_add(
                2_usize
                    .checked_mul(JobArg::ENCODED_LEN)
                    .expect("argv padding offset is bounded"),
            )
            .expect("argv padding offset is bounded");
        let pad = encoded.get_mut(pad_at).unwrap();
        *pad = 1;
        assert_eq!(
            JobArgv::decode_descriptor(&encoded),
            Err(ProviderError::NonCanonical)
        );
    }

    #[test]
    fn unused_arg_body_bytes_must_be_zero() {
        let arg = JobArg::try_from_bytes(b"prog").unwrap();
        let mut encoded = [0_u8; JobArg::ENCODED_LEN];
        arg.encode_descriptor(&mut encoded).unwrap();
        let last = JobArg::ENCODED_LEN
            .checked_sub(1)
            .expect("job arg encoding is non-empty");
        encoded[last] = 0x0a;
        assert_eq!(
            JobArg::decode_descriptor(&encoded),
            Err(ProviderError::NonCanonical)
        );
    }
}
