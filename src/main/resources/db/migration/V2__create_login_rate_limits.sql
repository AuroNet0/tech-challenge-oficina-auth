CREATE TABLE login_tentativas (
    chave VARCHAR(64) NOT NULL CHECK (chave ~ '^[0-9a-f]{64}$'),
    janela TIMESTAMPTZ NOT NULL,
    tentativas INTEGER NOT NULL CHECK (tentativas > 0),
    PRIMARY KEY (chave, janela)
);

CREATE INDEX idx_login_tentativas_janela ON login_tentativas(janela);
