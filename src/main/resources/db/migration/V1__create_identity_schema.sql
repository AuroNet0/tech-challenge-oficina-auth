CREATE TABLE usuarios (
    id UUID PRIMARY KEY,
    email VARCHAR(254) COLLATE "C" NOT NULL UNIQUE,
    nome VARCHAR(200) NOT NULL CHECK (length(trim(nome)) > 0),
    cpf VARCHAR(11) UNIQUE CHECK (cpf ~ '^[0-9]{11}$'),
    password_hash TEXT NOT NULL CHECK (password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$'),
    ativo BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em TIMESTAMPTZ NOT NULL,
    atualizado_em TIMESTAMPTZ NOT NULL,
    CHECK (email = lower(btrim(email)) AND email !~ '[[:space:]]' AND position('@' in email) > 1),
    CHECK (atualizado_em >= criado_em)
);

CREATE TABLE usuario_papeis (
    usuario_id UUID NOT NULL REFERENCES usuarios(id),
    papel VARCHAR(20) NOT NULL CHECK (papel IN ('CLIENTE', 'ATENDENTE', 'MECANICO', 'GERENTE')),
    PRIMARY KEY (usuario_id, papel)
);

CREATE INDEX idx_usuario_papeis_papel ON usuario_papeis(papel, usuario_id);

CREATE TABLE usuario_clientes (
    usuario_id UUID NOT NULL,
    papel VARCHAR(20) NOT NULL DEFAULT 'CLIENTE' CHECK (papel = 'CLIENTE'),
    cliente_id UUID NOT NULL,
    criado_em TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (usuario_id, cliente_id),
    FOREIGN KEY (usuario_id, papel) REFERENCES usuario_papeis(usuario_id, papel)
);

CREATE INDEX idx_usuario_clientes_cliente ON usuario_clientes(cliente_id, usuario_id);
