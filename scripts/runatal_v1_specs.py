"""Published in-band specification identities accepted by the independent reader."""

FORMAT_SPECIFICATION = (
    1,
    1,
    bytes.fromhex("8d6518e110478bf76b78d8fc13b3f92eef44d78bcfebcd59b9b1b720615a8a6a"),
)
CONTENT_CATALOG_SPECIFICATION = (
    1,
    1,
    bytes.fromhex("8f3999b066b666396259c4a92f9de7c5b8e67df9d38a69fb4fb824968b56ecdb"),
)
LEGACY_FORMAT_SPECIFICATIONS = {
    (1, 1, bytes.fromhex(digest))
    for digest in (
        "f9b69b9160bd48612d39f7bef3c43e6559b83436a54d23f928a145710fa20b74",
        "ac3e1ab1e82be24dae7cdef949698dd54d2407bc7f39fb30709dc36677eea61d",
        "f9b17fa5e6b4ac4562c7e4ab2da1f0c756da07945d808794ad75544a132b0d91",
        "62cded9a5b01fe75d7781b66303f5ffe8ced55a43025a0389eefaea5a0c58fe2",
        "35b446fbd19ca4ad0b1343b40c1a32b2eed8eef795034261a4092a0a2ae806fe",
        "d8f2cb250736799fd8b26f307e20c4d949d6cea1836614a5547210e82bbfcec1",
        "86390e5573cd6248eceeb5904bf9decb8929fe67aae638d531ab119418000e19",
        "32379c2a9e1d0fe166ac37f30d8772bd88d6c99a6ae31bb75cc7e8a8f4ce4307",
        "55c88679f00f3f8249eaf847fe4fba889f3f9f09e01048f5eb00e2d0d80c8e93",
        "9bf81709c78311fea1011137f8dab3b6cd8ffe6c8ea6040cfec7192efb89aba0",
        "39eba259587f8cacbee042788f2cbdc3e8064b8c48fc8ba93800ba02c8c60d32",
        "3991b59002c981fd3b5603badd4ea5b31143253023cba98050cfc7e928638aff",
        "c3fd6c43a5b6a05ffe11c339502ce35090f6643ee3070177e5802fc155d2b8c0",
        "82e46f53ba9bb2f52d6b942088d5965eaa17c2720e61ce842ed9d5e3c0d1219d",
        "900d1eface3294bc9e47369c0fcb64dca56ff334dfbc1288f349090e10c09e6f",
        "9d701dc87360e634b25b7b7f5d5e79315f9f27bcf4d50e09c2181e439b0c7d75",
        "58726b3c243c30ebc0941f656427520094a6bb10e7b2190be732b5a61300144d",
    )
}
