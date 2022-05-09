## 1.1.4
Support distinguishing requests by HTTP method.

## 1.1.2
Fixed a bug with file handling and another bug with inter-process communication.

## 1.1.1
Minor changes to prepare for merging upstream

## 1.1.0
The changes in this version were created by Shea Polansky from Independent Security Evaluators. Previous versions were created by Michal Dardas from LogicalTrust.net

### Added
- Different types of mocks
    - Basic --- the old behavior
    - URL redirects --- transparently redirect requests to a new URL
    - File Contents --- reads response from a specified file
    - Pipe to Process --- Pipe the (cleartext) request to a process and reply with the STDOUT from that process
    - CGI Script --- Call a CGI script and return the results
- Added UI features to access new functionality

### Changed
- Various internal API changes to support new functionality
- Now saves mock entries as JSON data in Burp's settings database
- Fixed a handful of UI bugs

## 1.0.2
### Added
- Confirm adding too large entryInput (optional)
- Do not display too large responses in editor (optional)

## 1.0.1
### Added
- Mock a branch in the Site Map
- Multi selection in the mock table
- Save to JSON / Load from JSON
