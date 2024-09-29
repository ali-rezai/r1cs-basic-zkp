mod r1cs;
use r1cs::{encrypt_with_g1, encrypt_with_g2, LRO};

fn main() {
    let witness = [1, 5, 1, 6, 25, 1];
    // let witness = [1, 7, 1, 18, 49, 1]; // also works

    let witness_g1 = encrypt_with_g1(&witness);
    let witness_g2 = encrypt_with_g2(&witness);

    let lro = LRO::new();
    lro.verify(&witness_g1, &witness_g2);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass() {
        let lro = LRO::new();

        let witness = [1, 5, 1, 6, 25, 1];
        let witness_g1 = encrypt_with_g1(&witness);
        let witness_g2 = encrypt_with_g2(&witness);
        lro.verify(&witness_g1, &witness_g2);

        let witness = [1, 7, 1, 18, 49, 1];
        let witness_g1 = encrypt_with_g1(&witness);
        let witness_g2 = encrypt_with_g2(&witness);
        lro.verify(&witness_g1, &witness_g2);
    }

    #[test]
    #[should_panic(expected = "Witness mismatch")]
    fn fail_witness_mismatch() {
        let witness = [1, 5, 1, 6, 25, 1];
        let witness_g1 = encrypt_with_g1(&witness);

        let witness = [1, 7, 1, 18, 49, 1];
        let witness_g2 = encrypt_with_g2(&witness);

        let lro = LRO::new();
        lro.verify(&witness_g1, &witness_g2);
    }

    #[test]
    #[should_panic(expected = "Verification failed")]
    fn fail_bad_witness() {
        let witness = [1, 6, 2, 6, 36, 4];
        let witness_g1 = encrypt_with_g1(&witness);
        let witness_g2 = encrypt_with_g2(&witness);

        let lro = LRO::new();
        lro.verify(&witness_g1, &witness_g2);
    }
}
