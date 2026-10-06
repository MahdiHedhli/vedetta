package iotsecurity

const FortiGuardSource = "https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure"

// Campaign file digests from FortiGuard Labs, published 2026-10-05 and reviewed
// 2026-10-06. The source includes downloader and backdoor components and repeats
// one hash; the 21 unique digests below identify campaign artifacts, not proof
// that a particular component executed. No sample was downloaded or executed.
var clingFortiGuardSHA256 = map[string]bool{
	"dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a": true,
	"a297eddfa7abea8d411afc0f150f8f6f30e470a77204de87e3b0815fa9bb8a84": true,
	"4fbd61cb9181ebbc4fe9a6e59d3c346dc00001da48d66bd890556fc6fad22b07": true,
	"121f2050e3c891b29565fd73451fff7ae60199c86eb8d79ec1eb1d9844578487": true,
	"48f9b72ce72ab7087794650d6eef10135345088384fbde1482f1c74a02b80302": true,
	"e6e113783356446aef66e5296db45b244f318292af7cebc2a9bd76f095a95c4c": true,
	"c1d8e2829ea63b9dc1cf2c3421a5093406adad4d6622e238376e78e908e0e6e8": true,
	"48962b3893f2c8261e32e6b95ea7d463d145a529a8b2a6c987dd979454405c73": true,
	"76692a23abe718b93e63edefd743971ec627c0cdf3778f856bd5ec88003deaa2": true,
	"ec199c78c11040fd3127887222fd75a85e5797bf96aa691a117fdd83dd663d81": true,
	"c0d8ffebfba969b1c1ca76bd9623bb623e9f95155c8ceca77d8fcc521435a497": true,
	"f49f45303cbfccee14ff193ac9608f860e6d616f08c0ecbef1ec44f7c863d7ec": true,
	"9391c6ad17aced1142607c0c623b18d86a7697cc483d204ffac94093e26b8068": true,
	"e4d12208789f36efc5a1ff765088fed95d6bb5972d1a804a4536fd42366797d4": true,
	"284e5ec8748f99fd1b8c331b699a5fe5fd4448bbaae0347a940f427f931c4d14": true,
	"6581bf37184bb2db899b9893064d39dd314ea691adf3281cc0aa7e0a31e5138a": true,
	"10d83c1748895361e07320f68d44d427b43cadd2cbffe0ab5e607ab03aec83da": true,
	"2ed54e0f988a62039abed88f6394eb1e3d5ed931f0183556055417fb08844ecf": true,
	"b90640b392827b4f2d280f6cf67860862953331917d42df23e1653a92f2f98ad": true,
	"dfba6008a2c828a9cb62342aec53006ae05a60cb8d4c41c3fa216fd727e8c6a3": true,
	"5c4e263546fb21f8fe8732789a5b6583eaa8ae11ebeef099462a7c9bf50e022d": true,
}
