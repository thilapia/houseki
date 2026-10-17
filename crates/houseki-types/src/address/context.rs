//! Declared context for recipient address interpretation.

use crate::{AddressFormatVersion, CryptoSuiteId, NetworkId};

/// The network, format version and cryptographic suite declared by an address.
///
/// These values determine the context in which a recipient descriptor is interpreted.
///
/// The descriptor also carries the recipient's ownership information and complete public
/// encapsulation key.
///
/// Construction preserves the supplied values without checking that their combination is
/// supported.
///
/// Before creating an output, the sender must check the intended network, supported format and
/// suite, and validate the complete descriptor under their rules.
///
/// This context alone does not establish a valid address or the intended recipient's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressContext {
    /// Declared network in which the address is interpreted.
    network_id: NetworkId,

    /// Declared recipient descriptor format.
    format_version: AddressFormatVersion,

    /// Declared suite for key validation, note encryption and recovery.
    crypto_suite_id: CryptoSuiteId,
}

impl AddressContext {
    /// Groups the declared address context without checking support.
    pub const fn new(
        network_id: NetworkId,
        format_version: AddressFormatVersion,
        crypto_suite_id: CryptoSuiteId,
    ) -> Self {
        Self {
            network_id,
            format_version,
            crypto_suite_id,
        }
    }

    /// Returns the intended network's genesis commitment.
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Returns the declared address format version.
    pub const fn format_version(&self) -> AddressFormatVersion {
        self.format_version
    }

    /// Returns the declared cryptographic suite identifier.
    pub const fn crypto_suite_id(&self) -> CryptoSuiteId {
        self.crypto_suite_id
    }
}
