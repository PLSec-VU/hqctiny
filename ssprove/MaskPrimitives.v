Set Warnings "-notation-overridden,-ambiguous-paths".
From mathcomp Require Import all_ssreflect all_algebra reals distr realsum ssralg.
From mathcomp Require Import poly polydiv qpoly.
Set Warnings "notation-overridden,ambiguous-paths".
Unset SsrOldRewriteGoalsOrder.
Open Scope ring_scope.
Import GRing.Theory.

From Stdlib Require Import Utf8.
From extructures Require Import ord fset fmap.
From Equations Require Import Equations.
Require Equations.Prop.DepElim.
Set Equations With UIP.
Set Bullet Behavior "Strict Subproofs".
Set Default Goal Selector "!".
Set Primitive Projections.

From HB Require Import structures.

From SSProve.Crypt Require Import NominalPrelude Package Prelude pkg_advantage.
Import PackageNotation.
#[local] Open Scope package_scope.
#[local] Open Scope ring_scope.

From SSProveHQC Require Import Tuple HQC HQCLethe DerivedMasks.

Module HQCLetheMaskPrimitives (P : HQCLetheParams).
  Include HQCLetheDerived P.
  Import HQC_Sec.

  Section StreamMask.

    Context (seed_bits stream_key_bits : nat).
    Context (coins_of_seed : 'I_(2 ^ seed_bits) -> Coins_t).
    Context (stream_key_of_seed : 'I_(2 ^ seed_bits) -> 'I_(2 ^ stream_key_bits)).
    Context (tau_of_seed : 'I_(2 ^ seed_bits) -> TauMask_t).
    Context (chacha_mask : 'I_(2 ^ stream_key_bits) -> MuMask_t).

    Definition mu_of_seed (theta : 'I_(2 ^ seed_bits)) : MuMask_t :=
      chacha_mask (stream_key_of_seed theta).

    Definition StreamKey_t := chFin (2 ^ stream_key_bits).
    Definition SeedOutputs_t := chProd Coins_t (chProd StreamKey_t TauMask_t).

    Definition SPLIT : ident := 5%N.
    Definition STREAM : ident := 6%N.

    Definition I_split : Interface :=
      [interface #val #[ SPLIT ] : 'unit → 'ch(SeedOutputs_t) ].
    Definition I_stream : Interface :=
      [interface #val #[ STREAM ] : 'unit → 'ch(MuMask_t) ].

    Definition SeedOutputsReal : package emptym I_split :=
      [package emptym ;
        #def #[ SPLIT ] (_ : 'unit) : 'ch(SeedOutputs_t) {
          theta ← sample uniform (2 ^ seed_bits) ;;
          ret (coins_of_seed theta, (stream_key_of_seed theta, tau_of_seed theta))
        }
      ].

    Definition SeedOutputsIndependent : package emptym I_split :=
      [package emptym ;
        #def #[ SPLIT ] (_ : 'unit) : 'ch(SeedOutputs_t) {
          theta ← sample uniform (2 ^ seed_bits) ;;
          key ← sample uniform (2 ^ stream_key_bits) ;;
          tau_fin ← sample uniform (2 ^ tau_bits) ;;
          ret (coins_of_seed theta, (key, tau_fin))
        }
      ].

    Definition StreamReal : package emptym I_stream :=
      [package emptym ;
        #def #[ STREAM ] (_ : 'unit) : 'ch(MuMask_t) {
          key ← sample uniform (2 ^ stream_key_bits) ;;
          ret (chacha_mask key)
        }
      ].

    Definition StreamIdeal : package emptym I_stream :=
      [package emptym ;
        #def #[ STREAM ] (_ : 'unit) : 'ch(MuMask_t) {
          mu_fin ← sample uniform (2 ^ mu_bits) ;;
          ret mu_fin
        }
      ].

    Definition R_split : package I_split I_derive :=
      [package emptym ;
        #def #[ DERIVE ] (_ : 'unit) : 'ch(Derived_t) {
          #import {sig #[ SPLIT ] : 'unit → 'ch(SeedOutputs_t)} as split ;;
          d ← split Datatypes.tt ;;
          let '(coins, (key, tau_fin)) := d in
          ret (coins, (chacha_mask key, tau_fin))
        }
      ].

    Definition R_stream : package I_stream I_derive :=
      [package emptym ;
        #def #[ DERIVE ] (_ : 'unit) : 'ch(Derived_t) {
          #import {sig #[ STREAM ] : 'unit → 'ch(MuMask_t)} as stream ;;
          theta ← sample uniform (2 ^ seed_bits) ;;
          mu_fin ← stream Datatypes.tt ;;
          tau_fin ← sample uniform (2 ^ tau_bits) ;;
          ret (coins_of_seed theta, (mu_fin, tau_fin))
        }
      ].

    Lemma seed_masks_are_split :
      MasksFromSeed seed_bits coins_of_seed mu_of_seed tau_of_seed
      ≈₀ (R_split ∘ SeedOutputsReal)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel arg.
      simplify_linking.
      eapply r_uniform_bij; [exact: id_bijective | move=> ? /=].
      apply: r_ret => s0 s1 ->. by split.
    Qed.

    Lemma independent_split_is_stream :
      (R_split ∘ SeedOutputsIndependent)%pack ≈₀ (R_stream ∘ StreamReal)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel arg.
      simplify_linking.
      do 3 (eapply r_uniform_bij; [exact: id_bijective | move=> ? /=]).
      apply: r_ret => s0 s1 ->. by split.
    Qed.

    Lemma ideal_stream_is_independent :
      (R_stream ∘ StreamIdeal)%pack ≈₀ MasksIndependentOfSeed seed_bits coins_of_seed.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel arg.
      simplify_linking.
      do 3 (eapply r_uniform_bij; [exact: id_bijective | move=> ? /=]).
      apply: r_ret => s0 s1 ->. by split.
    Qed.

    Theorem seed_masks_from_primitives :
      ∀ LB B,
        ValidPackage LB I_derive A_export B →
        AdvantageE (MasksFromSeed seed_bits coins_of_seed mu_of_seed tau_of_seed)
          (MasksIndependentOfSeed seed_bits coins_of_seed) B
        <= AdvantageE SeedOutputsReal SeedOutputsIndependent (B ∘ R_split)%pack
           + AdvantageE StreamReal StreamIdeal (B ∘ R_stream)%pack.
    Proof.
      move=> LB B VB.
      ssprove triangle (MasksFromSeed seed_bits coins_of_seed mu_of_seed tau_of_seed) [::
        (R_split ∘ SeedOutputsReal)%pack ;
        (R_split ∘ SeedOutputsIndependent)%pack ;
        (R_stream ∘ StreamReal)%pack ;
        (R_stream ∘ StreamIdeal)%pack
      ] (MasksIndependentOfSeed seed_bits coins_of_seed) B as ineq.
      eapply Order.POrderTheory.le_trans; first exact: ineq.
      erewrite (seed_masks_are_split LB B VB); try fmap_solve.
      erewrite (independent_split_is_stream LB B VB); try fmap_solve.
      erewrite (ideal_stream_is_independent LB B VB); try fmap_solve.
      by rewrite GRing.add0r !GRing.addr0 !Advantage_link.
    Qed.

  End StreamMask.

End HQCLetheMaskPrimitives.

Module HQCLetheMaskPrimitivesFor (H : HQCParams) (M : CRTModuli H).
  Module Params <: HQCLetheParams.
    Include H.
    Include M.
  End Params.
  Include HQCLetheMaskPrimitives Params.
End HQCLetheMaskPrimitivesFor.

Module HQCLetheMaskPrimitives1 (E : HQC1Encoding) (M : CRTModuli HQC1Consts).
  Module Base := HQC1 E.
  Include HQCLetheMaskPrimitivesFor Base M.
End HQCLetheMaskPrimitives1.
Module HQCLetheMaskPrimitives3 (E : HQC3Encoding) (M : CRTModuli HQC3Consts).
  Module Base := HQC3 E.
  Include HQCLetheMaskPrimitivesFor Base M.
End HQCLetheMaskPrimitives3.
Module HQCLetheMaskPrimitives5 (E : HQC5Encoding) (M : CRTModuli HQC5Consts).
  Module Base := HQC5 E.
  Include HQCLetheMaskPrimitivesFor Base M.
End HQCLetheMaskPrimitives5.
