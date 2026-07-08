-- Table 1: Clean US column naming
CREATE TABLE us_customers (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(100),
    email VARCHAR(100),
    ssn VARCHAR(20),
    itin VARCHAR(20),
    phone VARCHAR(20),
    zip_code VARCHAR(10),
    credit_card VARCHAR(25),
    state VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW(),
    drivers_license VARCHAR(30)
);

-- Table 2: Obscure column naming (no PII hints)
CREATE TABLE records_archive (
    id SERIAL PRIMARY KEY,
    field_a VARCHAR(100),
    field_b VARCHAR(20),
    field_c VARCHAR(20),
    field_d VARCHAR(25),
    field_e VARCHAR(20),
    field_f VARCHAR(10),
    field_g VARCHAR(30),
    notes TEXT
);

-- Table 3: Financial transactions
CREATE TABLE financial_records (
    id SERIAL PRIMARY KEY,
    transaction_id VARCHAR(30),
    card_number VARCHAR(25),
    card_holder VARCHAR(100),
    billing_zip VARCHAR(10),
    account_phone VARCHAR(20),
    amount NUMERIC(12,2),
    transaction_date TIMESTAMP
);

-- Table 4: HR records
CREATE TABLE hr_records (
    id SERIAL PRIMARY KEY,
    employee_name VARCHAR(100),
    work_email VARCHAR(100),
    tax_id VARCHAR(20),
    personal_phone VARCHAR(20),
    home_zip VARCHAR(10),
    employment_type VARCHAR(20),
    salary NUMERIC(10,2)
);

-- Table 5: No PII — negative control
CREATE TABLE system_logs (
    id SERIAL PRIMARY KEY,
    log_level VARCHAR(20),
    service_name VARCHAR(50),
    message TEXT,
    request_id VARCHAR(50),
    duration_ms INT,
    logged_at TIMESTAMP
);
