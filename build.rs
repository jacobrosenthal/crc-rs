extern crate build_const;

include!("src/util.rs");

#[allow(non_snake_case)]
fn create_constants() {
    let mut crc16 = build_const::ConstWriter::for_build("crc16_constants")
        .unwrap()
        .finish_dependencies();
    let X25: u16 = 0x1021;
    crc16.add_value("X25", "u16", X25);
    crc16.add_array("X25_TABLE", "u16", &make_table_crc16(X25, true));

    let POLY_8005: u16 = 0x8005;
    crc16.add_value("POLY_8005", "u16", POLY_8005);
    crc16.add_array("POLY_8005_TABLE", "u16", &make_table_crc16(POLY_8005, true));

    crc16.finish();

    let mut crc32 = build_const::ConstWriter::for_build("crc32_constants")
        .unwrap()
        .finish_dependencies();
    let CASTAGNOLI: u32 = 0x1EDC6F41;
    crc32.add_value("CASTAGNOLI", "u32", CASTAGNOLI);
    crc32.add_array(
        "CASTAGNOLI_TABLE",
        "u32",
        &make_table_crc32(CASTAGNOLI, true),
    );

    let IEEE: u32 = 0x04C11DB7;
    crc32.add_value("IEEE", "u32", IEEE);
    crc32.add_array("IEEE_TABLE", "u32", &make_table_crc32(IEEE, true));

    let KOOPMAN: u32 = 0x741B8CD7;
    crc32.add_value("KOOPMAN", "u32", KOOPMAN);
    crc32.add_array("KOOPMAN_TABLE", "u32", &make_table_crc32(KOOPMAN, true));

    crc32.finish();

    let mut crc64 = build_const::ConstWriter::for_build("crc64_constants")
        .unwrap()
        .finish_dependencies();

    let ECMA: u64 = 0x42F0E1EBA9EA3693;
    crc64.add_value("ECMA", "u64", ECMA);
    crc64.add_array("ECMA_TABLE", "u64", &make_table_crc64(ECMA, true));

    let ISO: u64 = 0x000000000000001B;
    crc64.add_value("ISO", "u64", ISO);
    crc64.add_array("ISO_TABLE", "u64", &make_table_crc64(ISO, true));

    crc64.finish();
}

fn main() {
    create_constants();
}
