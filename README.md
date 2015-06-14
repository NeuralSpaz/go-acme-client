go-acme-client is a ACME client which tries to take away the magic; it needs
manual handling of the challenge response, although it aids the administrator
in the process.

THIS IS NOT FINISHED, AND CURRENTLY WON'T BUILD WITHOUT AN UNPATCHED
"github.com/square/go-jose" (requires the replay-token feature).