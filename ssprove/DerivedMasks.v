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

From SSProveHQC Require Import Tuple HQC HQCLethe.

Module HQCLetheDerived (P : HQCLetheParams).
  Include HQCLethe P.
  Import HQC_Sec.

  Definition Coins_t := chFin ('C(n, we) ^ 3).
  Definition MuMask_t := chFin (2 ^ mu_bits).
  Definition TauMask_t := chFin (2 ^ tau_bits).
  Definition Derived_t := chProd Coins_t (chProd MuMask_t TauMask_t).

  Definition DERIVE : ident := 1%N.

  Definition I_derive : Interface :=
    [interface
      #val #[ DERIVE ] : 'unit → 'ch(Derived_t)
    ].

  Definition hqc_ciphertext (pk : PublicKey_t) (msg : Message_t) (t_fin : Coins_t)
    : Ciphertext_t :=
    let h := fin_to_rq pk.1 in
    let s := fin_to_rq pk.2 in
    let m := P.encode msg in
    let '(r1_fin, r2_fin, e_fin) := split_fin3 t_fin in
    let r1 := \val (fin_to_rq_we r1_fin) in
    let r2 := \val (fin_to_rq_we r2_fin) in
    let e  := \val (fin_to_rq_we e_fin) in
    (rq_to_fin (r1 + h * r2), rq_to_fin (truncate (m + s * r2 + e))).

  Definition lethe_reply (h_fin : Rq_ct) (ss : Residues_t) (msg : Message_t)
    (t_fin : Coins_t) (mu_fin : MuMask_t) (tau_fin : TauMask_t) : Reply_t :=
    let '(r1_fin, r2_fin, e_fin) := split_fin3 t_fin in
    let r1 := \val (fin_to_rq_we r1_fin) in
    let r2 := \val (fin_to_rq_we r2_fin) in
    let e  := \val (fin_to_rq_we e_fin) in
    let h := fin_to_rq h_fin in
    let m := (P.encode msg : {poly 'F_2}) in
    (rq_to_fin (r1 + h * r2),
     server_replies ss r2 e m
       (fin_to_poly mu_bits mu_fin) (fin_to_poly tau_bits tau_fin)).

  Definition simulated_reply (ss : Residues_t) (c : Ciphertext_t)
    (mu_fin : MuMask_t) (tau_fin : TauMask_t) : Reply_t :=
    (c.1,
     cut_residues (fin_to_poly n c.2 + 'X ^+ n1n2 * fin_to_poly tau_bits tau_fin
                   + fin_to_poly mu_bits mu_fin * Ring.gen)).

  Definition MasksUniformCoins : package emptym I_derive :=
    [package emptym ;
      #def #[ DERIVE ] (_ : 'unit) : 'ch(Derived_t) {
        t_fin ← sample uniform ('C(n, we) ^ 3) ;;
        mu_fin ← sample uniform (2 ^ mu_bits) ;;
        tau_fin ← sample uniform (2 ^ tau_bits) ;;
        ret (t_fin, (mu_fin, tau_fin))
      }
    ].

  Definition Reply_from_derivation : package I_derive I_hqclethe_encrypt :=
    [package emptym ;
      #def #[ HQCLETHE_ENC ] (args : 'ch(Request_t)) : 'ch(Reply_t) {
        #import {sig #[ DERIVE ] : 'unit → 'ch(Derived_t)} as derive ;;
        let '(h_fin, (ss, msg)) := args in
        if valid_residues ss then
          d ← derive Datatypes.tt ;;
          let '(t_fin, (mu_fin, tau_fin)) := d in
          ret (lethe_reply h_fin ss msg t_fin mu_fin tau_fin)
        else
          fail
      }
    ].

  Definition unreduced_v (s_fin : Rq_ct) (msg : Message_t) (t_fin : Coins_t)
    : {poly 'F_2} :=
    let '(_, r2_fin, e_fin) := split_fin3 t_fin in
    (P.encode msg : {poly 'F_2})
    + fin_to_poly n s_fin * \val (fin_to_rq_we r2_fin)
    + \val (fin_to_rq_we e_fin).

  Lemma lethe_reply_shift h_fin ss msg s_fin t_fin mu_fin tau_fin :
    crt_witness ss = Some s_fin ->
    let Pc := unreduced_v s_fin msg t_fin in
    lethe_reply h_fin ss msg t_fin mu_fin tau_fin
    = simulated_reply ss (hqc_ciphertext (h_fin, s_fin) msg t_fin)
        (f_mu Pc mu_fin) (f_tau Pc tau_fin).
  Proof.
    move=> Ew.
    have Hmatch := crt_witness_some _ _ Ew.
    rewrite /lethe_reply /hqc_ciphertext /simulated_reply /unreduced_v.
    rewrite /split_fin3 /=.
    set r2 := sval (fin_to_rq_we (tnth _ (inord 1))).
    set e := sval (fin_to_rq_we (tnth _ (inord 2))).
    set s := fin_to_poly n s_fin.
    set Pc := ((P.encode msg : {poly 'F_2}) + s * r2 + e)%R.
    have HszP : (size Pc <= n + mu_bits)%N.
    { apply: size_cipher_poly; first [exact: size_Rq_val | exact: size_fin_to_poly]. }
    congr pair.
    have Hsum : (P.encode msg + fin_to_rq s_fin * r2 + e : Ring.Rq)
                = in_qpoly Ring.gen Pc.
    { have H3 := in_qpoly_rq_eq3 (P.encode msg) (fin_to_rq s_fin) r2 e.
      rewrite fin_to_rq_val in H3.
      apply: val_inj.
      exact: H3. }
    rewrite Hsum truncate_in_qpoly.
    rewrite (server_replies_cut_residues _ s _ _ _ _ _ Hmatch).
    congr cut_residues.
    exact: mask_identity.
  Qed.

  Lemma id_bijective (T : Type) : bijective (@id T).
  Proof. exact: (@Bijective _ _ id id (fun x => erefl) (fun x => erefl)). Qed.

  Lemma uniform_derivation_is_hqclethe :
    (Reply_from_derivation ∘ MasksUniformCoins)%pack ≈₀ hqclethe_encrypt.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel m.
    destruct m as [h_fin [ss msg]].
    simplify_linking.
    case: (valid_residues ss).
    - simplify_linking.
      do 3 (eapply r_uniform_bij; [exact: id_bijective | move=> ? /=]).
      apply: r_ret. by move=> s0 s1 ->.
    - simplify_linking. apply: r_fail.
  Qed.

  Section SeedDerivation.

    Context (seed_bits : nat).
    Context (coins_of_seed : 'I_(2 ^ seed_bits) -> Coins_t).
    Context (mu_of_seed : 'I_(2 ^ seed_bits) -> MuMask_t).
    Context (tau_of_seed : 'I_(2 ^ seed_bits) -> TauMask_t).

    Definition MasksFromSeed : package emptym I_derive :=
      [package emptym ;
        #def #[ DERIVE ] (_ : 'unit) : 'ch(Derived_t) {
          theta ← sample uniform (2 ^ seed_bits) ;;
          ret (coins_of_seed theta, (mu_of_seed theta, tau_of_seed theta))
        }
      ].

    Definition MasksIndependentOfSeed : package emptym I_derive :=
      [package emptym ;
        #def #[ DERIVE ] (_ : 'unit) : 'ch(Derived_t) {
          theta ← sample uniform (2 ^ seed_bits) ;;
          mu_fin ← sample uniform (2 ^ mu_bits) ;;
          tau_fin ← sample uniform (2 ^ tau_bits) ;;
          ret (coins_of_seed theta, (mu_fin, tau_fin))
        }
      ].

    Definition hqclethe_encrypt_seeded : package emptym I_hqclethe_encrypt :=
      [package emptym ;
        #def #[ HQCLETHE_ENC ] (args : 'ch(Request_t)) : 'ch(Reply_t) {
          let '(h_fin, (ss, msg)) := args in
          if valid_residues ss then
            theta ← sample uniform (2 ^ seed_bits) ;;
            ret (lethe_reply h_fin ss msg (coins_of_seed theta)
                   (mu_of_seed theta) (tau_of_seed theta))
          else
            fail
        }
      ].

    Definition hqc_encrypt_seeded : package emptym I_hqc_encrypt :=
      [package emptym ;
        #def #[ HQC_ENC ] (args : 'ch(chProd PublicKey_t Message_t)) : 'ch(Ciphertext_t) {
          let '(pk, msg) := args in
          theta ← sample uniform (2 ^ seed_bits) ;;
          ret (hqc_ciphertext pk msg (coins_of_seed theta))
        }
      ].

    Lemma seeded_is_reduction :
      hqclethe_encrypt_seeded ≈₀ (Reply_from_derivation ∘ MasksFromSeed)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel m.
      destruct m as [h_fin [ss msg]].
      simplify_linking.
      case: (valid_residues ss).
      - simplify_linking.
        eapply r_uniform_bij; first exact: id_bijective.
        intro theta. simpl.
        apply: r_ret. by move=> s0 s1 ->.
      - simplify_linking. apply: r_fail.
    Qed.

    Lemma independent_masks_simulated :
      (Reply_from_derivation ∘ MasksIndependentOfSeed)%pack
      ≈₀ (Sim ∘ hqc_encrypt_seeded)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel m.
      destruct m as [h_fin [ss msg]].
      simplify_linking.
      case Ew: (crt_witness ss) => [s_fin|].
      - rewrite (crt_witness_valid _ _ Ew).
        simplify_linking.
        eapply r_uniform_bij; first exact: id_bijective.
        intro theta. simpl.
        pose Pc := unreduced_v s_fin msg (coins_of_seed theta).
        eapply r_uniform_bij.
        Unshelve. 3: exact (f_mu Pc).
        { apply: f_mu_bij. }
        intro mu_fin. simpl.
        eapply r_uniform_bij.
        Unshelve. 3: exact (f_tau Pc).
        { apply: f_tau_bij. }
        intro tau_fin. simpl.
        apply: r_ret => s0 s1 ->. split; last done.
        exact: lethe_reply_shift.
      - rewrite (crt_witness_none _ Ew).
        simplify_linking.
        apply: r_fail.
    Qed.

    Theorem seeded_masks_simulatable :
      ∀ LA A,
        ValidPackage LA I_hqclethe_encrypt A_export A →
        AdvantageE hqclethe_encrypt_seeded (Sim ∘ hqc_encrypt_seeded)%pack A
        <= AdvantageE MasksFromSeed MasksIndependentOfSeed
             (A ∘ Reply_from_derivation)%pack.
    Proof.
      move=> LA A VA.
      ssprove triangle hqclethe_encrypt_seeded [::
        (Reply_from_derivation ∘ MasksFromSeed)%pack ;
        (Reply_from_derivation ∘ MasksIndependentOfSeed)%pack
      ] (Sim ∘ hqc_encrypt_seeded)%pack A as ineq.
      eapply Order.POrderTheory.le_trans; first exact: ineq.
      erewrite (seeded_is_reduction LA A VA); try fmap_solve.
      erewrite (independent_masks_simulated LA A VA); try fmap_solve.
      by rewrite GRing.add0r GRing.addr0 Advantage_link.
    Qed.

    Theorem seeded_masks_simulatable_uniform_coins :
      ∀ LA A,
        ValidPackage LA I_hqclethe_encrypt A_export A →
        AdvantageE hqclethe_encrypt_seeded (Sim ∘ hqc_encrypt)%pack A
        <= AdvantageE MasksFromSeed MasksUniformCoins
             (A ∘ Reply_from_derivation)%pack.
    Proof.
      move=> LA A VA.
      ssprove triangle hqclethe_encrypt_seeded [::
        (Reply_from_derivation ∘ MasksFromSeed)%pack ;
        (Reply_from_derivation ∘ MasksUniformCoins)%pack ;
        (hqclethe_encrypt : raw_package)
      ] (Sim ∘ hqc_encrypt)%pack A as ineq.
      eapply Order.POrderTheory.le_trans; first exact: ineq.
      erewrite (seeded_is_reduction LA A VA); try fmap_solve.
      erewrite (uniform_derivation_is_hqclethe LA A VA); try fmap_solve.
      erewrite (hqclethe_indistinguishable LA A VA); try fmap_solve.
      by rewrite GRing.add0r !GRing.addr0 Advantage_link.
    Qed.

  End SeedDerivation.

End HQCLetheDerived.

Module HQCLetheDerivedFor (H : HQCParams) (M : CRTModuli H).
  Module Params <: HQCLetheParams.
    Include H.
    Include M.
  End Params.
  Include HQCLetheDerived Params.
End HQCLetheDerivedFor.

Module HQCLetheDerived1 (E : HQC1Encoding) (M : CRTModuli HQC1Consts).
  Module Base := HQC1 E.
  Include HQCLetheDerivedFor Base M.
End HQCLetheDerived1.
Module HQCLetheDerived3 (E : HQC3Encoding) (M : CRTModuli HQC3Consts).
  Module Base := HQC3 E.
  Include HQCLetheDerivedFor Base M.
End HQCLetheDerived3.
Module HQCLetheDerived5 (E : HQC5Encoding) (M : CRTModuli HQC5Consts).
  Module Base := HQC5 E.
  Include HQCLetheDerivedFor Base M.
End HQCLetheDerived5.
