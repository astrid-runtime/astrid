#![no_main]

use astrid_config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };

    let value_result = toml::from_str::<toml::Value>(src);
    let config_result = toml::from_str::<Config>(src);

    if let Ok(config) = config_result {
        assert!(
            value_result.is_ok(),
            "typed config deserialization implies syntactically valid TOML"
        );

        let serialized = toml::to_string(&config).expect("parsed config must serialize");
        let roundtrip: Config =
            toml::from_str(&serialized).expect("serialized config must deserialize");
        let _ = astrid_config::validate::validate(&roundtrip);
    }
});
