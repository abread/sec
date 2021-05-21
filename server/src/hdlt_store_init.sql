CREATE TABLE IF NOT EXISTS proximity_proofs (
    epoch BIGINT,
    prover_id INT,
    prover_position_x BIGINT,
    prover_position_y BIGINT,
    request_signature BLOB,
    witness_id INT,
    witness_position_x BIGINT,
    witness_position_y BIGINT,
    signature BLOB,

    PRIMARY KEY (epoch, prover_id, witness_id, prover_position_x, prover_position_y, witness_position_x, witness_position_y)
);

CREATE VIEW IF NOT EXISTS misbehavior_proofs AS
WITH all_misbehavior_proofs AS (
    WITH users AS (
        SELECT prover_id AS id FROM proximity_proofs
        UNION
        SELECT witness_id AS id FROM proximity_proofs
    )
    SELECT a.epoch AS epoch,
        users.id AS user_id,
        a.prover_id AS a_prover_id,
        a.prover_position_x AS a_prover_position_x,
        a.prover_position_y AS a_prover_position_y,
        a.request_signature AS a_request_signature,
        a.witness_id AS a_witness_id,
        a.witness_position_x AS a_witness_position_x,
        a.witness_position_y AS a_witness_position_y,
        a.signature AS a_signature,
        b.prover_id AS b_prover_id,
        b.prover_position_x AS b_prover_position_x,
        b.prover_position_y AS b_prover_position_y,
        b.request_signature AS b_request_signature,
        b.witness_id AS b_witness_id,
        b.witness_position_x AS b_witness_position_x,
        b.witness_position_y AS b_witness_position_y,
        b.signature AS b_signature,
        ROW_NUMBER() OVER (
            PARTITION BY a.epoch, users.id
            /* impose some total order on misbehavior proofs to ensure convergence */
            ORDER BY a.prover_id ASC, a.prover_position_x ASC, a.prover_position_y ASC, a.request_signature ASC, a.witness_id ASC, a.witness_position_x ASC, a.witness_position_y ASC, a.signature ASC, b.prover_id ASC, b.prover_position_x ASC, b.prover_position_y ASC, b.request_signature ASC, b.witness_id ASC, b.witness_position_x ASC, b.witness_position_y ASC, b.signature ASC
        ) AS rank
    FROM proximity_proofs AS a, proximity_proofs AS b, users
    WHERE a.epoch = b.epoch
        AND a.rowid != b.rowid
        AND (
            /* prover-prover conflicts are no longer possible, because we only accept one prover proof per epoch
               clients reading will figure out if a user was sending different proofs to different servers
            (
                a.prover_id = users.id
                AND a.prover_id = b.prover_id
                AND (a.prover_position_x != b.prover_position_x OR a.prover_position_y != b.prover_position_y)
            )
            OR */
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
SELECT epoch,
    user_id,
    a_prover_id,
    a_prover_position_x,
    a_prover_position_y,
    a_request_signature,
    a_witness_id,
    a_witness_position_x,
    a_witness_position_y,
    a_signature,
    b_prover_id,
    b_prover_position_x,
    b_prover_position_y,
    b_request_signature,
    b_witness_id,
    b_witness_position_x,
    b_witness_position_y,
    b_signature
FROM all_misbehavior_proofs WHERE rank = 1;