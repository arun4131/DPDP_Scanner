-- Database-level reproduction for the scanner's pre-detection chunking bug.
-- Run this inside a disposable PostgreSQL database.

DROP TABLE IF EXISTS chunking_document_reproduction;

CREATE TABLE chunking_document_reproduction (
    id                      integer PRIMARY KEY,
    short_json_control      text,
    long_formatted_json     text,
    short_xml_control       text,
    long_formatted_xml      text,
    short_query_control     text,
    long_query_control      text,
    short_base64_control    text,
    long_base64_document    text,
    long_text_duplicate     text
);

INSERT INTO chunking_document_reproduction (
    id,
    short_json_control,
    long_formatted_json,
    short_xml_control,
    long_formatted_xml,
    short_query_control,
    long_query_control,
    short_base64_control,
    long_base64_document,
    long_text_duplicate
)
VALUES (
    1,

    -- Short controls prove that the extractors work before chunking is involved.
    '{"cvv":"312"}',

    -- Valid JSON. Whitespace inside the padding value makes the current
    -- whitespace-based Chunks helper divide it before JSON parsing. The exact
    -- padding positions the cvv key and its value on different chunks.
    '{"padding":"' || repeat('ordinary words ', 28) || repeat('x', 64) ||
        '", "cvv" : "312"}',

    '<root><cvv>312</cvv></root>',

    -- Valid XML longer than 512 bytes. It is divided into XML fragments before
    -- the XML decoder sees it, so the internal cvv key/value can be lost.
    '<root><padding>' || repeat('ordinary words ', 45) ||
        '</padding> <cvv>312</cvv></root>',

    'cvv=312&note=short-control',

    -- This is intentionally an unbroken query string. It is >512 bytes but has
    -- no whitespace, demonstrating that length alone is not the trigger.
    'padding=' || repeat('x', 650) || '&cvv=312',

    encode(convert_to('{"cvv":"312"}', 'UTF8'), 'base64'),

    -- PostgreSQL's base64 encoder inserts line breaks in long output. PushValue
    -- splits on those newlines before Base64 decoding, so the document is lost.
    encode(
        convert_to(
            '{"padding":"' || repeat('x', 650) || '","cvv":"312"}',
            'UTF8'
        ),
        'base64'
    ),

    -- One database cell with the same email in separate scanner chunks. The
    -- current implementation reports two matches and accumulated weight 2.0
    -- even though only one cell was scanned.
    'duplicate@example.com ' || repeat('ordinary words ', 80) ||
        'duplicate@example.com'
);

-- Inspect the fixtures and confirm which values exceed 512 bytes.
SELECT
    id,
    octet_length(short_json_control)   AS short_json_bytes,
    octet_length(long_formatted_json)  AS long_json_bytes,
    octet_length(short_xml_control)    AS short_xml_bytes,
    octet_length(long_formatted_xml)   AS long_xml_bytes,
    octet_length(short_query_control)  AS short_query_bytes,
    octet_length(long_query_control)   AS long_query_bytes,
    octet_length(short_base64_control) AS short_base64_bytes,
    octet_length(long_base64_document) AS long_base64_bytes,
    octet_length(long_text_duplicate)  AS long_text_bytes
FROM chunking_document_reproduction;

-- Ground truth: each structured column contains one context-confirmed CVV.
-- long_text_duplicate contains one original cell and two occurrences of the
-- same email; row-level match counting should still count that cell only once.
