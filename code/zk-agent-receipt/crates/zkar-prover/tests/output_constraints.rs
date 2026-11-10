//! Show that each output slot of the uniform step circuit is pinned by the
//! constraints themselves: flipping one output variable's assignment breaks
//! satisfiability. This is a single-variable check on recorded constraints,
//! not a soundness proof of the whole proof system.

use std::collections::HashSet;

use ff::Field;
use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use nova_snark::traits::circuit::StepCircuit;
use zkar_prover::{
    issuance::Fixture,
    relation::{TraceStep, UniformCircuit, STATE_ARITY},
    F,
};

const SEED_A: u64 = 0x4345_5254_494b_0001;

// Each constraint is (A, B, C, annotation path).
type RecordedConstraint = (LinearCombination<F>, LinearCombination<F>, LinearCombination<F>, String);

/// A constraint system that records every assignment and every constraint.
/// It mirrors how Nova's TestConstraintSystem works, but keeps the data in a
/// form the test can inspect and perturb.
#[derive(Debug)]
struct RecordingCs {
    // One assignment per variable, in allocation order.
    inputs: Vec<F>,
    aux: Vec<F>,
    constraints: Vec<RecordedConstraint>,
    // Namespace stack, joined with '/' like the library does.
    namespace: Vec<String>,
    // Paths already used, so duplicate names are caught like in the library.
    paths: HashSet<String>,
}

impl RecordingCs {
    fn new() -> Self {
        // Input 0 is the constant one, as in the library.
        RecordingCs {
            inputs: vec![F::ONE],
            aux: vec![],
            constraints: vec![],
            namespace: vec![],
            paths: HashSet::new(),
        }
    }

    fn path(&self, name: &str) -> String {
        assert!(!name.contains('/'), "'/' is not allowed in names");
        if self.namespace.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", self.namespace.join("/"), name)
        }
    }

    fn eval(&self, lc: &LinearCombination<F>) -> F {
        let mut acc = F::ZERO;
        for (index, coeff) in lc.iter_inputs() {
            acc += self.inputs[*index] * coeff;
        }
        for (index, coeff) in lc.iter_aux() {
            acc += self.aux[*index] * coeff;
        }
        acc
    }

    fn is_satisfied(&self) -> bool {
        self.constraints.iter().all(|(a, b, c, _)| {
            let mut lhs = self.eval(a);
            lhs *= self.eval(b);
            lhs == self.eval(c)
        })
    }

    /// Would the system still be satisfied if `var` held `value` instead?
    /// The change is temporary; the honest assignment is restored after.
    fn satisfied_if(&mut self, var: Variable, value: F) -> bool {
        let slot = match var.get_unchecked() {
            Index::Input(i) => &mut self.inputs[i],
            Index::Aux(i) => &mut self.aux[i],
        };
        let honest = *slot;
        *slot = value;
        let ok = self.is_satisfied();
        let slot = match var.get_unchecked() {
            Index::Input(i) => &mut self.inputs[i],
            Index::Aux(i) => &mut self.aux[i],
        };
        *slot = honest;
        ok
    }
}

impl ConstraintSystem<F> for RecordingCs {
    type Root = Self;

    fn alloc<Fn, A, AR>(&mut self, annotation: A, f: Fn) -> Result<Variable, SynthesisError>
    where
        Fn: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let path = self.path(&annotation().into());
        assert!(self.paths.insert(path.clone()), "duplicate path: {path}");
        self.aux.push(f()?);
        Ok(Variable::new_unchecked(Index::Aux(self.aux.len() - 1)))
    }

    fn alloc_input<Fn, A, AR>(&mut self, annotation: A, f: Fn) -> Result<Variable, SynthesisError>
    where
        Fn: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let path = self.path(&annotation().into());
        assert!(self.paths.insert(path.clone()), "duplicate path: {path}");
        self.inputs.push(f()?);
        Ok(Variable::new_unchecked(Index::Input(self.inputs.len() - 1)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    {
        let path = self.path(&annotation().into());
        assert!(self.paths.insert(path.clone()), "duplicate path: {path}");
        self.constraints
            .push((a(LinearCombination::zero()), b(LinearCombination::zero()), c(LinearCombination::zero()), path));
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name = name_fn().into();
        let path = self.path(&name);
        assert!(self.paths.insert(path.clone()), "duplicate path: {path}");
        self.namespace.push(name);
    }

    fn pop_namespace(&mut self) {
        assert!(self.namespace.pop().is_some());
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

/// Synthesize one step circuit on the honest input state.
/// Returns the system, the input variables and the output numbers.
fn synthesize(
    step: &TraceStep<UniformCircuit>,
) -> (RecordingCs, Vec<Variable>, Vec<AllocatedNum<F>>) {
    let mut cs = RecordingCs::new();
    let z: Vec<_> = step
        .input
        .iter()
        .enumerate()
        .map(|(i, v)| AllocatedNum::alloc(cs.namespace(|| format!("z_{i}")), || Ok(*v)))
        .collect::<Result<_, _>>()
        .unwrap();
    let z_vars: Vec<Variable> = z.iter().map(|n| n.get_variable()).collect();
    let out = step
        .circuit
        .synthesize(&mut cs, &z)
        .expect("honest witness must synthesize");
    assert_eq!(out.len(), STATE_ARITY);
    (cs, z_vars, out)
}

#[test]
fn a18_every_output_variable_is_pinned_by_constraints() {
    let trace = Fixture::benchmark_deterministic(4, 8, 3, SEED_A)
        .unwrap()
        .uniform_steps();
    // An arbitrary constant that has nothing to do with the trace.
    let unrelated = F::from(0x_c0ff_ee11u64);

    let mut checked = 0usize;
    let mut skipped = 0usize;
    let mut free: Vec<String> = vec![];

    for (fold, step) in trace.iter().enumerate() {
        let (mut cs, z_vars, out) = synthesize(step);
        assert!(cs.is_satisfied(), "honest fold {fold} is unsatisfied");

        for (slot, num) in out.iter().enumerate() {
            let var = num.get_variable();
            if z_vars.contains(&var) {
                // Pass-through slot: the output is the input variable itself.
                // Changing it changes the input, which is not an output forgery.
                skipped += 1;
                continue;
            }
            let value = num.get_value().unwrap();
            for (name, repl) in [("value+1", value + F::ONE), ("unrelated", unrelated)] {
                if cs.satisfied_if(var, repl) {
                    free.push(format!("fold {fold} slot {slot} with {name}"));
                }
            }
            checked += 1;
        }
    }

    eprintln!("output slots checked: {checked}, pass-through slots skipped: {skipped}");
    assert!(checked > 0, "every slot was a pass-through; test checked nothing");
    assert!(free.is_empty(), "free output slots: {:?}", free);
}

/// A circuit whose single output is a fresh variable with no constraint.
/// The perturbation check must report it as still satisfied.
#[derive(Clone)]
struct FreeOutputCircuit;

impl StepCircuit<F> for FreeOutputCircuit {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // Constrain the input a little so the system is not empty. The output
        // is a fresh variable and no constraint mentions it.
        let input = &z[0];
        let out = AllocatedNum::alloc(cs.namespace(|| "free output"), || Ok(F::from(7u64)))?;
        cs.enforce(
            || "trivial bookkeeping on the input",
            |lc| lc + input.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + input.get_variable(),
        );
        Ok(vec![out])
    }
}

#[test]
fn a19_self_check_detects_a_free_output() {
    let mut cs = RecordingCs::new();
    let z = vec![AllocatedNum::alloc(cs.namespace(|| "z_0"), || Ok(F::from(3u64))).unwrap()];
    let out = FreeOutputCircuit
        .synthesize(&mut cs, &z)
        .unwrap();
    assert!(cs.is_satisfied(), "self-check circuit must be satisfied");
    // Nothing mentions the output variable, so any replacement must leave
    // the system satisfied.
    let var = out[0].get_variable();
    let value = out[0].get_value().unwrap();
    assert!(
        cs.satisfied_if(var, value + F::ONE),
        "self-check failed: the check cannot detect a free output"
    );
    assert!(
        cs.satisfied_if(var, F::from(0x_c0ff_ee11u64)),
        "self-check failed for an unrelated constant"
    );
}
