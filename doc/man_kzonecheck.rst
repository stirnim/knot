.. highlight:: console

kzonecheck – Knot DNS zone file checking tool
=============================================

Synopsis
--------

:program:`kzonecheck` [*options*] *filename*

Description
-----------

The utility checks zone file syntax and runs semantic checks on the zone
content. The executed checks are the same as the checks run by the Knot
DNS server.

Please, refer to the ``semantic-checks`` configuration option in
:manpage:`knot.conf(5)` for the full list of available semantic checks.

Options
.......

**-o**, **--origin** *origin*
  Zone origin. If not specified, the origin is determined from the file name
  (possibly removing the ``.zone`` suffix).

**-t**, **--time** *time*
  Specify to check zone for different time (key expiration).
  Use timestamp, YYYY-MM-DD format or +/- time.

**-v**, **--verbose**
  Enable debug output.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
