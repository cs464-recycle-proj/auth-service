create schema user;
use user;

CREATE TABLE users (
    id BINARY(16) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
delete from users;
# user password = Password123!
INSERT INTO users (id, created_at, email, password, role, updated_at)
VALUES (
    '5b42d6b3-57e4-4f3b-9360-2e8db8b74129',  
    '2025-10-11 12:38:33.311612',
    'testuser@gmail.com',
    '$2a$10$OTAkblAOGeW.8VdL7ldlf.vB.yxi4ZUm/8muyCHHC.KcErsokxMBa',  
    'USER',
    '2025-10-11 12:38:33.311612'
);

# admin password = Password123!
INSERT INTO users (id, created_at, email, password, role, updated_at)
VALUES (
    'b6f98d3b-9f7b-4d2e-9b3a-9a4a2f5d12b7',  
    '2025-10-11 12:38:33.311612',
    'testadmin@gmail.com',
    '$2a$10$OTAkblAOGeW.8VdL7ldlf.vB.yxi4ZUm/8muyCHHC.KcErsokxMBa',  
    'ADMIN',
    '2025-10-11 12:38:33.311612'
);