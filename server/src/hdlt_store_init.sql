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

CREATE VIEW IF NOT EXISTS malicious_proofs AS
WITH all_malicious_proofs AS (
    WITH users AS (
        SELECT prover_id AS id FROM proximity_proofs
        UNION
        SELECT witness_id AS id FROM proximity_proofs
    )
    SELECT a.epoch AS epoch,
        users.id AS malicious_user_id,
        a.rowid AS proof_left_id,
        b.rowid AS proof_right_id,
        ROW_NUMBER() OVER (
            PARTITION BY a.epoch, users.id
            /* impose some total order on malicious proofs to ensure convergence */
            ORDER BY a.prover_id ASC, a.prover_position_x ASC, a.prover_position_y ASC, a.request_signature ASC, a.witness_id ASC, a.witness_position_x ASC, a.witness_position_y ASC, a.signature ASC, b.prover_id ASC, b.prover_position_x ASC, b.prover_position_y ASC, b.request_signature ASC, b.witness_id ASC, b.witness_position_x ASC, b.witness_position_y ASC, b.signature ASC
        ) AS rank
    FROM proximity_proofs AS a, proximity_proofs AS b, users
    WHERE a.epoch = b.epoch
        AND a.rowid != b.rowid
        AND (
            (
                /* prover-prover conflicts */
                a.prover_id = users.id
                AND a.prover_id = b.prover_id
                AND (a.prover_position_x != b.prover_position_x OR a.prover_position_y != b.prover_position_y)
            )
            OR
            (
                /* prover-witness conflicts (and witness-prover: just swap tables a and b) */
                a.prover_id = users.id
                AND a.prover_id = b.witness_id
                AND (a.prover_position_x != b.witness_position_x OR a.prover_position_y != b.witness_position_y)
            )
            OR
            (
                /* witness-witness conflicts */
                a.witness_id = users.id
                AND a.witness_id = b.witness_id
                AND (a.witness_position_x != b.witness_position_x OR a.witness_position_y != b.witness_position_y)
            )
        )
)
SELECT epoch, malicious_user_id, proof_left_id, proof_right_id FROM all_malicious_proofs WHERE rank = 1;