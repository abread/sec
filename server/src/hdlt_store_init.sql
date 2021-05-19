CREATE TABLE IF NOT EXISTS proximity_proofs (
    rowid INTEGER,

    epoch BIGINT,
    prover_id INT,
    prover_position_x BIGINT,
    prover_position_y BIGINT,
    request_signature BLOB,
    witness_id INT,
    witness_position_x BIGINT,
    witness_position_y BIGINT,
    signature BLOB,

    PRIMARY KEY (rowid ASC),
    UNIQUE (epoch, prover_id, witness_id, prover_position_x, prover_position_y, witness_position_x, witness_position_y)
);

CREATE TABLE IF NOT EXISTS malicious_proofs (
    epoch BIGINT,
    malicious_user_id INT,
    proof_left_id INT,
    proof_right_id INT,

    PRIMARY KEY (epoch, malicious_user_id)
);

CREATE TRIGGER IF NOT EXISTS failure_detector
    AFTER INSERT ON proximity_proofs
    FOR EACH ROW
    BEGIN
        /* detect prover teleportation within same epoch */
        INSERT OR REPLACE INTO malicious_proofs (epoch, malicious_user_id, proof_left_id, proof_right_id)
        SELECT a.epoch, a.prover_id, a.rowid, b.rowid FROM proximity_proofs AS a, proximity_proofs AS b
        WHERE a.epoch = b.epoch
            AND a.rowid != b.rowid
            AND a.prover_id = b.prover_id
            AND (a.prover_position_x != b.prover_position_x OR a.prover_position_y != b.prover_position_y)
            AND a.prover_id = NEW.prover_id
        /* impose some total order on malicious proofs to ensure convergence */
        ORDER BY a.prover_position_x ASC, a.prover_position_y ASC, a.request_signature ASC, a.witness_id ASC, a.witness_position_x ASC, a.witness_position_y ASC, a.signature ASC, b.prover_position_x ASC, b.prover_position_y ASC, b.request_signature ASC, b.witness_id ASC, b.witness_position_x ASC, b.witness_position_y ASC, b.signature ASC
        LIMIT 1;

        /* detect witness teleportation within same epoch */
        INSERT OR REPLACE INTO malicious_proofs (epoch, malicious_user_id, proof_left_id, proof_right_id)
        SELECT a.epoch, a.witness_id, a.rowid, b.rowid FROM proximity_proofs AS a, proximity_proofs AS b
        WHERE a.epoch = b.epoch
            AND a.rowid != b.rowid
            AND a.witness_id = b.witness_id
            AND (a.witness_position_x != b.witness_position_x OR a.witness_position_y != b.witness_position_y)
            AND a.witness_id = NEW.witness_id
        /* impose some total order on malicious proofs to ensure convergence */
        ORDER BY a.prover_position_x ASC, a.prover_position_y ASC, a.request_signature ASC, a.witness_id ASC, a.witness_position_x ASC, a.witness_position_y ASC, a.signature ASC, b.prover_position_x ASC, b.prover_position_y ASC, b.request_signature ASC, b.witness_id ASC, b.witness_position_x ASC, b.witness_position_y ASC, b.signature ASC
        LIMIT 1;

        /* detect prover-witness teleportation within same epoch */
        INSERT OR REPLACE INTO malicious_proofs (epoch, malicious_user_id, proof_left_id, proof_right_id)
        SELECT a.epoch, a.prover_id, a.rowid, b.rowid FROM proximity_proofs AS a, proximity_proofs AS b
        WHERE a.epoch = b.epoch
            AND a.rowid != b.rowid
            AND a.prover_id = b.witness_id
            AND (a.prover_position_x != b.witness_position_x OR a.prover_position_y != b.witness_position_y)
            AND (a.prover_id = NEW.prover_id OR b.witness_id = NEW.witness_id)
        /* impose some total order on malicious proofs to ensure convergence */
        ORDER BY a.prover_position_x ASC, a.prover_position_y ASC, a.request_signature ASC, a.witness_id ASC, a.witness_position_x ASC, a.witness_position_y ASC, a.signature ASC, b.prover_position_x ASC, b.prover_position_y ASC, b.request_signature ASC, b.witness_id ASC, b.witness_position_x ASC, b.witness_position_y ASC, b.signature ASC
        LIMIT 1;
    END;