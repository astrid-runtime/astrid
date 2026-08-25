//! Structured jobs. Decode may be mismatched; start rejects.

use astrid_resource_types::{CausalRequestId, OperationId};

use crate::argv::JobArgv;
use crate::attachment::{AttachmentSet, StreamSet};
use crate::closure::{ApplicationClosure, decode_resource, encode_resource};
use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, read_nested,
    require_exact_len, write_header, write_nested,
};
use crate::error::ProviderError;
use crate::instance::{AdmittedInstance, InstanceId};
use crate::principal::HostPrincipal;

/// One execution request bound to an admitted instance.
///
/// [`Job::for_instance`] copies instance and closure identities. A decoded job
/// may disagree with an instance; [`crate::check_binding`] rejects that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    operation: OperationId,
    instance: InstanceId,
    closure: ApplicationClosure,
    argv: JobArgv,
    attachments: AttachmentSet,
    streams: StreamSet,
    causal: CausalRequestId,
    principal: HostPrincipal,
}

impl Job {
    /// Exact encoded length, including nested descriptors and zero padding.
    pub const ENCODED_LEN: usize = 1185;

    /// Copy instance identities onto a structured job.
    #[must_use]
    pub const fn for_instance(
        operation: OperationId,
        instance: &AdmittedInstance,
        argv: &JobArgv,
        attachments: &AttachmentSet,
        streams: &StreamSet,
        causal: CausalRequestId,
        principal: HostPrincipal,
    ) -> Self {
        Self {
            operation,
            instance: instance.id(),
            closure: instance.closure(),
            argv: *argv,
            attachments: *attachments,
            streams: *streams,
            causal,
            principal,
        }
    }

    /// Construct claimed identities without binding checks.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn claiming(
        operation: OperationId,
        instance: InstanceId,
        closure: ApplicationClosure,
        argv: &JobArgv,
        causal: CausalRequestId,
        principal: HostPrincipal,
    ) -> Self {
        Self {
            operation,
            instance,
            closure,
            argv: *argv,
            attachments: AttachmentSet::EMPTY,
            streams: StreamSet::EMPTY,
            causal,
            principal,
        }
    }

    /// Operation identity of this job.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Instance this job claims. May disagree with an admitted descriptor.
    #[must_use]
    pub const fn instance(&self) -> InstanceId {
        self.instance
    }

    /// Closure this job claims.
    #[must_use]
    pub const fn closure(&self) -> ApplicationClosure {
        self.closure
    }

    /// Structured argv. Not a shell line.
    #[must_use]
    pub const fn argv(&self) -> &JobArgv {
        &self.argv
    }

    /// Opaque attachments. Not host paths.
    #[must_use]
    pub const fn attachments(&self) -> &AttachmentSet {
        &self.attachments
    }

    /// Opaque streams. Not live handles.
    #[must_use]
    pub const fn streams(&self) -> &StreamSet {
        &self.streams
    }

    /// Causal request identity carried on the later receipt.
    #[must_use]
    pub const fn causal(&self) -> CausalRequestId {
        self.causal
    }

    /// Host principal seam for this job.
    #[must_use]
    pub const fn principal(&self) -> HostPrincipal {
        self.principal
    }
}

impl DescriptorEncode for Job {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        require_exact_len(output, Self::ENCODED_LEN)?;
        write_header(output, ProviderTypeTag::Job)?;
        encode_job_body(self, output)
    }
}

fn encode_job_body(job: &Job, output: &mut [u8]) -> Result<(), ProviderError> {
    let offset = encode_resource(output, 3, &job.operation)?;
    let offset = write_nested(output, offset, &job.instance)?;
    let offset = write_nested(output, offset, &job.closure)?;
    let offset = write_nested(output, offset, &job.argv)?;
    let offset = write_nested(output, offset, &job.attachments)?;
    let offset = write_nested(output, offset, &job.streams)?;
    let offset = encode_resource(output, offset, &job.causal)?;
    write_nested(output, offset, &job.principal)?;
    Ok(())
}

impl DescriptorDecode for Job {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::Job)?;
        decode_job_body(input)
    }
}

fn decode_job_body(input: &[u8]) -> Result<Job, ProviderError> {
    let (operation, offset) = decode_resource::<OperationId>(input, 3, 19)?;
    let (instance, offset) = read_nested::<InstanceId>(input, offset, InstanceId::ENCODED_LEN)?;
    let (closure, offset) =
        read_nested::<ApplicationClosure>(input, offset, ApplicationClosure::ENCODED_LEN)?;
    let (argv, offset) = read_nested::<JobArgv>(input, offset, JobArgv::ENCODED_LEN)?;
    let (attachments, offset) =
        read_nested::<AttachmentSet>(input, offset, AttachmentSet::ENCODED_LEN)?;
    let (streams, offset) = read_nested::<StreamSet>(input, offset, StreamSet::ENCODED_LEN)?;
    let (causal, offset) = decode_resource::<CausalRequestId>(input, offset, 19)?;
    let (principal, _) = read_nested::<HostPrincipal>(input, offset, HostPrincipal::ENCODED_LEN)?;
    Ok(Job {
        operation,
        instance,
        closure,
        argv,
        attachments,
        streams,
        causal,
        principal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProviderError;
    use crate::fixtures::{honest_instance, honest_job, honest_principal};
    use crate::provider::check_binding;
    use astrid_resource_types::{ObjectGeneration, ResourceId};

    #[test]
    fn for_instance_copies_identities_and_roundtrips() {
        let instance = honest_instance();
        let job = honest_job().unwrap();
        assert_eq!(job.instance(), instance.id());
        assert_eq!(job.closure(), instance.closure());
        check_binding(&instance, &job).unwrap();
        let mut encoded = [0_u8; Job::ENCODED_LEN];
        job.encode_descriptor(&mut encoded).unwrap();
        assert_eq!(Job::decode_descriptor(&encoded), Ok(job));
        let mut leftover = [0_u8; Job::ENCODED_LEN];
        leftover.copy_from_slice(&encoded);
        let mut leftover_extra = [0_u8; { Job::ENCODED_LEN + 1 }];
        leftover_extra[..Job::ENCODED_LEN].copy_from_slice(&leftover);
        leftover_extra[Job::ENCODED_LEN] = 1;
        assert_eq!(
            Job::decode_descriptor(&leftover_extra),
            Err(ProviderError::InvalidLength)
        );
    }

    #[test]
    fn decoded_mismatch_is_preserved_until_binding() {
        let instance = honest_instance();
        let mismatched = Job::claiming(
            honest_job().unwrap().operation(),
            InstanceId::new(
                ResourceId::from_bytes([0xfe; 32]),
                ObjectGeneration::INITIAL,
            ),
            instance.closure(),
            honest_job().unwrap().argv(),
            honest_job().unwrap().causal(),
            honest_principal(),
        );
        let mut encoded = [0_u8; Job::ENCODED_LEN];
        mismatched.encode_descriptor(&mut encoded).unwrap();
        let decoded = Job::decode_descriptor(&encoded).unwrap();
        assert_eq!(decoded, mismatched);
        assert_eq!(
            check_binding(&instance, &decoded),
            Err(ProviderError::TypeMismatch)
        );
    }
}
