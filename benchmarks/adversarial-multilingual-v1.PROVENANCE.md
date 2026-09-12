# Adversarial multilingual ambiguity corpus v1

This is a synthetic safety corpus, not an independent accuracy corpus. It contains deliberately
underspecified ERP and finance headers in German, French, Spanish, English, Italian and Portuguese.
Every label is an explicit abstention because the source header does not contain enough meaning to
choose among the target concepts safely.

The corpus exists to prevent a seemingly smarter matcher from turning lexical resemblance into an
unsafe automatic decision. It may be extended with real, independently labelled examples, but those
must retain their own source-family and licensing provenance instead of being relabelled as synthetic.
