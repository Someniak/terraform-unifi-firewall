# Changelog

All notable changes to this project will be documented in this file.

## [0.7.0] - 2026-07-20

### Added
- `unifi_fixedip` supports reservations for devices that have never connected: the provider creates the client record when the MAC is unknown, and a `created_by_provider` attribute controls whether destroy fully removes the record or only clears the reservation.

### Fixed
- Integration `setup.sh` no longer aborts with a bare error on a failed or locked login, so the setup-wizard instructions are shown as intended.

## [0.3.2] - 2026-02-21

### Fixed
- Improved handling of `allow_return_traffic` in firewall policies to prevent persistent diffs.
- Corrected default values for optional filters (`Description`, `IPsecFilter`, `ConnectionStateFilter`) in state mapping.
- Fixed mapping of traffic filters when reading from the UniFi API.

## [0.3.1] - 2026-02-21

### Fixed
- Stability fixes for optional attributes to reduce unnecessary diffs.

## [0.3.0] - 2026-02-21

### Added
- Initial support for complex firewall policies with combined filters.
- Support for `unifi_fw` and `unifi_dns` resource naming.
