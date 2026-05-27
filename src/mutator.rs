use rand::Rng;

pub struct Mutator{
    rng : rand::rngs::ThreadRng,
}

impl Mutator {
    pub fn new() -> Self {
        Mutator {
            rng: rand::rng(),
        }
    }
}