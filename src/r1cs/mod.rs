// y^2 = 4x^3 + 2z + 9
//
// Constraints:
// v1 = y*y
// v2 = x*x
// v1 - 2z - 9 = v2*4x
//
// Witness:
// [1, y, x, z, v1, v2]
//

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

mod utils;
use utils::to_scalar;
pub use utils::{encrypt_with_g1, encrypt_with_g2};

pub struct LRO {
    left: Vec<Vec<Scalar>>,
    right: Vec<Vec<Scalar>>,
    output: Vec<Vec<Scalar>>,
}

impl LRO {
    pub fn new() -> Self {
        LRO {
            left: to_scalar(&[
                vec![0, 1, 0, 0, 0, 0],
                vec![0, 0, 1, 0, 0, 0],
                vec![0, 0, 0, 0, 0, 1],
            ]),
            right: to_scalar(&[
                vec![0, 1, 0, 0, 0, 0],
                vec![0, 0, 1, 0, 0, 0],
                vec![0, 0, 4, 0, 0, 0],
            ]),
            output: to_scalar(&[
                vec![0, 0, 0, 0, 1, 0],
                vec![0, 0, 0, 0, 0, 1],
                vec![-9, 0, 0, -2, 1, 0],
            ]),
        }
    }

    fn verify_witness_equality(witness_g1: &[G1Affine], witness_g2: &[G2Affine]) {
        witness_g1
            .iter()
            .zip(witness_g2.iter())
            .for_each(|(g1, g2)| {
                if pairing(&g1, &G2Affine::generator()) != pairing(&G1Affine::generator(), &g2) {
                    panic!("Witness mismatch");
                }
            });
    }

    pub fn verify(&self, witness_g1: &[G1Affine], witness_g2: &[G2Affine]) {
        LRO::verify_witness_equality(witness_g1, witness_g2);

        self.left
            .iter()
            .zip(self.right.iter())
            .enumerate()
            .for_each(|(step, (left, right))| {
                let mut g1 = G1Projective::identity();
                left.iter()
                    .enumerate()
                    .for_each(|(index, val)| g1 += val * witness_g1[index]);

                let mut g2 = G2Projective::identity();
                right
                    .iter()
                    .enumerate()
                    .for_each(|(index, val)| g2 += val * witness_g2[index]);

                let mut g1_out = G1Projective::identity();
                self.output[step]
                    .iter()
                    .enumerate()
                    .for_each(|(index, val)| g1_out += val * witness_g1[index]);

                if pairing(&G1Affine::from(g1), &G2Affine::from(g2))
                    != pairing(&G1Affine::from(g1_out), &G2Affine::generator())
                {
                    panic!("Verification failed");
                }
            });
    }
}
