# Synthetic access sample

`kavach-access-sample.csv` is a synthetic sign-in/access export for trying the
Access watch importer. It contains no real people, credentials or traffic.

Use **Try a synthetic sample** on `/access/`, or choose the file manually.
Expected result: 36 events across two days, with failed sign-ins, a password
spray, a success after failure, MFA denials, impossible travel, off-hours
activity, a new country, legacy authentication and access to the default
critical assets.

Required columns are `timestamp`, `user` and `result`. The sample also includes
country, city, latitude/longitude, ASN, target, application, authentication,
reason, MFA and privilege so the geography and critical-asset views work.

To use a real export:

1. Export from Entra ID, Active Directory, SAP, VPN/ZTNA or your SIEM as CSV or
   a JSON array.
2. Keep the rows on the authorized host until they are ready to analyze.
3. Open `/access/` and drop the file in. The file is parsed in the browser and
   is never uploaded.
