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

Module HQCLetheSession (P : HQCLetheParams).
  Include HQCLetheDerived P.
  Import HQC_Sec.

  Lemma polyF2_of_nat0 pos len : polyF2_of_nat 0 pos len = 0.
  Proof.
    elim: len pos => [|len IH] pos //=.
    by rewrite IH addr0 scale0r.
  Qed.

  Lemma polyF2_of_nat_extend m pos len extra :
    (m < 2 ^ len)%N ->
    polyF2_of_nat m pos (len + extra) = polyF2_of_nat m pos len.
  Proof.
    elim: len m pos => [|len IH] m pos.
    - rewrite expn0 ltnS leqn0 => /eqP ->.
      by rewrite add0n polyF2_of_nat0.
    - move=> Hm.
      have Hdiv : (m %/ 2 < 2 ^ len)%N.
      { by rewrite ltn_divLR // -expnSr. }
      by rewrite addSn /= IH.
  Qed.

  Lemma polyF2_of_nat_long m pos len1 len2 :
    (m < 2 ^ len1)%N -> (m < 2 ^ len2)%N ->
    polyF2_of_nat m pos len1 = polyF2_of_nat m pos len2.
  Proof.
    case: (leqP len1 len2) => Hle H1 H2.
    - by rewrite -(subnKC Hle) polyF2_of_nat_extend.
    - by rewrite -(subnKC (ltnW Hle)) polyF2_of_nat_extend.
  Qed.

  Lemma residue_of_natK (p : {poly 'F_2}) :
    residue_of_nat (nat_of_residue p) = p.
  Proof.
    rewrite /residue_of_nat /nat_of_residue.
    set N := nat_of_polyF2 p 0 (size p).
    rewrite (polyF2_of_nat_long N 0 N (size p)).
    - exact: ltn_expl.
    - exact: nat_of_polyF2_bound.
    - by rewrite /N polyF2_takeK take_poly_id.
  Qed.

  Definition residues_of (s_fin : Rq_ct) : Residues_t :=
    cut_residues (fin_to_poly n s_fin).

  Lemma residues_of_match s_fin :
    residues_match (fin_to_poly n s_fin) (residues_of s_fin).
  Proof.
    rewrite /residues_match /residues_of /cut_residues.
    elim: moduli => [|f fs IH] //=.
    by rewrite residue_of_natK eqxx IH.
  Qed.

  Lemma crt_witness_residues_of s_fin :
    crt_witness (residues_of s_fin) = Some s_fin.
  Proof.
    rewrite /crt_witness.
    case: pickP => [x Hx | Hnone].
    - congr Some.
      exact: crt_witness_unique Hx (residues_of_match s_fin).
    - by move: (Hnone s_fin); rewrite residues_of_match.
  Qed.

  Section SessionKey.

    Context (seed_bits : nat).
    Context (coins_of_seed : 'I_(2 ^ seed_bits) -> Coins_t).
    Context (mu_of_seed : 'I_(2 ^ seed_bits) -> MuMask_t).
    Context (tau_of_seed : 'I_(2 ^ seed_bits) -> TauMask_t).

    Context (hseed_bits keygen_bits salt_bits key_bits : nat).
    Context (auth_bits session_bits transcript_bits : nat).
    Context (Aux_t Tag_t : choice_type).

    Definition HSeed_t := chFin (2 ^ hseed_bits).
    Definition ClientPK_t := chProd HSeed_t Rq_ct.
    Definition Salt_t := chFin (2 ^ salt_bits).
    Definition Key_t := chFin (2 ^ key_bits).
    Definition AuthKey_t := chFin (2 ^ auth_bits).
    Definition SessionKey_t := chFin (2 ^ session_bits).
    Definition TranscriptKey_t := chFin (2 ^ transcript_bits).
    Definition Seed_t := chFin (2 ^ seed_bits).
    Definition KemCt_t := chProd Ciphertext_t Salt_t.
    Definition Encaps_t := chProd ClientPK_t (chProd KemCt_t Key_t).
    Definition MaskedEncaps_t := chProd Encaps_t (chProd MuMask_t TauMask_t).
    Definition KdfOut_t := chProd SessionKey_t TranscriptKey_t.
    Definition SessionArg_t := chProd AuthKey_t Aux_t.
    Definition View_t :=
      chProd ClientPK_t
        (chProd Residues_t (chProd Salt_t (chProd Reply_t (chProd Tag_t SessionKey_t)))).

    Context (h_of_seed : HSeed_t -> Rq_ct).
    Context (keygen : 'I_(2 ^ keygen_bits) -> ClientPK_t).
    Context (fo_derive : ClientPK_t -> Message_t -> Salt_t -> Key_t * Seed_t).
    Context (kdf : Key_t -> AuthKey_t -> KdfOut_t).
    Context (confirm : TranscriptKey_t -> ClientPK_t -> Salt_t -> Aux_t -> Tag_t).

    Definition hqc_pk (pk : ClientPK_t) : PublicKey_t := (h_of_seed pk.1, pk.2).

    Definition session_view (pk : ClientPK_t) (salt : Salt_t) (reply : Reply_t)
      (keys : KdfOut_t) (aux : Aux_t) (ks_out : SessionKey_t) : View_t :=
      (pk, (residues_of pk.2, (salt, (reply, (confirm keys.2 pk salt aux, ks_out))))).

    Definition exported_key (replace : bool) (keys : KdfOut_t) (fresh : SessionKey_t)
      : SessionKey_t :=
      if replace then fresh else keys.1.

    Definition SESSION : ident := 2%N.
    Definition ENCAPS : ident := 3%N.
    Definition KDF : ident := 4%N.

    Definition I_session : Interface :=
      [interface #val #[ SESSION ] : 'ch(SessionArg_t) → 'ch(View_t) ].
    Definition I_encaps : Interface :=
      [interface #val #[ ENCAPS ] : 'unit → 'ch(Encaps_t) ].
    Definition I_masked_encaps : Interface :=
      [interface #val #[ ENCAPS ] : 'unit → 'ch(MaskedEncaps_t) ].
    Definition I_kdf : Interface :=
      [interface #val #[ KDF ] : 'ch(AuthKey_t) → 'ch(KdfOut_t) ].

    Definition SessionReal : package emptym I_session :=
      [package emptym ;
        #def #[ SESSION ] (arg : 'ch(SessionArg_t)) : 'ch(View_t) {
          let '(k_auth, aux) := arg in
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          let pk := keygen kc in
          let '(K, theta) := fo_derive pk msg salt in
          let reply := lethe_reply (h_of_seed pk.1) (residues_of pk.2) msg
                         (coins_of_seed theta) (mu_of_seed theta) (tau_of_seed theta) in
          let keys := kdf K k_auth in
          ret (session_view pk salt reply keys aux keys.1)
        }
      ].

    Definition Session (replace : bool) : package emptym I_session :=
      [package emptym ;
        #def #[ SESSION ] (arg : 'ch(SessionArg_t)) : 'ch(View_t) {
          let '(k_auth, aux) := arg in
          fresh ← sample uniform (2 ^ session_bits) ;;
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          let pk := keygen kc in
          let '(K, theta) := fo_derive pk msg salt in
          let reply := lethe_reply (h_of_seed pk.1) (residues_of pk.2) msg
                         (coins_of_seed theta) (mu_of_seed theta) (tau_of_seed theta) in
          let keys := kdf K k_auth in
          ret (session_view pk salt reply keys aux (exported_key replace keys fresh))
        }
      ].

    Definition SessionIdeal : package emptym I_session := Session true.

    Definition encaps_with (pk : ClientPK_t) (msg : Message_t) (salt : Salt_t)
      (K : Key_t) (theta : Seed_t) : Encaps_t :=
      (pk, ((hqc_ciphertext (hqc_pk pk) msg (coins_of_seed theta), salt), K)).

    Definition encaps_of (pk : ClientPK_t) (msg : Message_t) (salt : Salt_t)
      : Encaps_t :=
      let '(K, theta) := fo_derive pk msg salt in encaps_with pk msg salt K theta.

    Definition KEMReal : package emptym I_encaps :=
      [package emptym ;
        #def #[ ENCAPS ] (_ : 'unit) : 'ch(Encaps_t) {
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          ret (encaps_of (keygen kc) msg salt)
        }
      ].

    Definition KEMIdeal : package emptym I_encaps :=
      [package emptym ;
        #def #[ ENCAPS ] (_ : 'unit) : 'ch(Encaps_t) {
          K' ← sample uniform (2 ^ key_bits) ;;
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          let e := encaps_of (keygen kc) msg salt in
          ret (e.1, (e.2.1, K'))
        }
      ].

    Definition masked_overflow (pk : ClientPK_t) (msg : Message_t) (theta : Seed_t)
      : chProd MuMask_t TauMask_t :=
      let Pc := unreduced_v pk.2 msg (coins_of_seed theta) in
      (f_mu Pc (mu_of_seed theta), f_tau Pc (tau_of_seed theta)).

    Definition MasksHideOverflow : package emptym I_masked_encaps :=
      [package emptym ;
        #def #[ ENCAPS ] (_ : 'unit) : 'ch(MaskedEncaps_t) {
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          let pk := keygen kc in
          ret (encaps_of pk msg salt, masked_overflow pk msg (fo_derive pk msg salt).2)
        }
      ].

    Definition OverflowUniform : package emptym I_masked_encaps :=
      [package emptym ;
        #def #[ ENCAPS ] (_ : 'unit) : 'ch(MaskedEncaps_t) {
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          a ← sample uniform (2 ^ mu_bits) ;;
          t ← sample uniform (2 ^ tau_bits) ;;
          ret (encaps_of (keygen kc) msg salt, (a, t))
        }
      ].

    Definition KDFReal : package emptym I_kdf :=
      [package emptym ;
        #def #[ KDF ] (k_auth : 'ch(AuthKey_t)) : 'ch(KdfOut_t) {
          K ← sample uniform (2 ^ key_bits) ;;
          ret (kdf K k_auth)
        }
      ].

    Definition KDFIdeal : package emptym I_kdf :=
      [package emptym ;
        #def #[ KDF ] (_ : 'ch(AuthKey_t)) : 'ch(KdfOut_t) {
          ks ← sample uniform (2 ^ session_bits) ;;
          kt ← sample uniform (2 ^ transcript_bits) ;;
          ret (ks, kt)
        }
      ].

    Definition view_of_encaps (replace : bool) (e : Encaps_t) (a : MuMask_t)
      (t : TauMask_t) (k_auth : AuthKey_t) (aux : Aux_t) (fresh : SessionKey_t)
      : View_t :=
      let '(pk, ((c, salt), K)) := e in
      let keys := kdf K k_auth in
      session_view pk salt (simulated_reply (residues_of pk.2) c a t) keys aux
        (exported_key replace keys fresh).

    Definition R_masks (replace : bool) : package I_masked_encaps I_session :=
      [package emptym ;
        #def #[ SESSION ] (arg : 'ch(SessionArg_t)) : 'ch(View_t) {
          #import {sig #[ ENCAPS ] : 'unit → 'ch(MaskedEncaps_t)} as encaps ;;
          let '(k_auth, aux) := arg in
          fresh ← sample uniform (2 ^ session_bits) ;;
          d ← encaps Datatypes.tt ;;
          ret (view_of_encaps replace d.1 d.2.1 d.2.2 k_auth aux fresh)
        }
      ].

    Definition R_kem (replace : bool) : package I_encaps I_session :=
      [package emptym ;
        #def #[ SESSION ] (arg : 'ch(SessionArg_t)) : 'ch(View_t) {
          #import {sig #[ ENCAPS ] : 'unit → 'ch(Encaps_t)} as encaps ;;
          let '(k_auth, aux) := arg in
          fresh ← sample uniform (2 ^ session_bits) ;;
          e ← encaps Datatypes.tt ;;
          a ← sample uniform (2 ^ mu_bits) ;;
          t ← sample uniform (2 ^ tau_bits) ;;
          ret (view_of_encaps replace e a t k_auth aux fresh)
        }
      ].

    Definition R_kdf (replace : bool) : package I_kdf I_session :=
      [package emptym ;
        #def #[ SESSION ] (arg : 'ch(SessionArg_t)) : 'ch(View_t) {
          #import {sig #[ KDF ] : 'ch(AuthKey_t) → 'ch(KdfOut_t)} as derive ;;
          let '(k_auth, aux) := arg in
          fresh ← sample uniform (2 ^ session_bits) ;;
          keys ← derive k_auth ;;
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          a ← sample uniform (2 ^ mu_bits) ;;
          t ← sample uniform (2 ^ tau_bits) ;;
          let pk := keygen kc in
          let c := (encaps_of pk msg salt).2.1.1 in
          ret (session_view pk salt (simulated_reply (residues_of pk.2) c a t) keys aux
                 (exported_key replace keys fresh))
        }
      ].


    Lemma real_is_session_false : SessionReal ≈₀ Session false.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel arg.
      destruct arg as [k_auth aux].
      apply: r_dead_sample_R.
      do 3 (eapply r_uniform_bij; [exact: id_bijective | move=> ? /=]).
      case: (fo_derive _ _ _) => K theta /=.
      apply: r_ret => s0 s1 ->. by split.
    Qed.

    Lemma session_is_masks_reduction b :
      Session b ≈₀ (R_masks b ∘ MasksHideOverflow)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel arg.
      destruct arg as [k_auth aux].
      simplify_linking.
      eapply r_uniform_bij; first exact: id_bijective. move=> fresh /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> kc /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> msg /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> salt /=.
      rewrite /encaps_of /masked_overflow.
      case: (fo_derive (keygen kc) msg salt) => K theta /=.
      apply: r_ret => s0 s1 ->. split; last done.
      rewrite /view_of_encaps /encaps_with /=.
      congr session_view.
      exact: (lethe_reply_shift _ _ _ _ _ _ _ (crt_witness_residues_of _)).
    Qed.

    Lemma uniform_overflow_is_kem_reduction b :
      (R_masks b ∘ OverflowUniform)%pack ≈₀ (R_kem b ∘ KEMReal)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel arg.
      destruct arg as [k_auth aux].
      simplify_linking.
      do 6 (eapply r_uniform_bij; [exact: id_bijective | move=> ? /=]).
      apply: r_ret => s0 s1 ->. by split.
    Qed.

    Lemma ideal_kem_is_kdf_reduction b :
      (R_kem b ∘ KEMIdeal)%pack ≈₀ (R_kdf b ∘ KDFReal)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel arg.
      destruct arg as [k_auth aux].
      simplify_linking.
      eapply r_uniform_bij; first exact: id_bijective. move=> fresh /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> K /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> kc /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> msg /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> salt /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> a /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> t /=.
      rewrite /encaps_of.
      case: (fo_derive (keygen kc) msg salt) => K0 theta /=.
      apply: r_ret => s0 s1 ->. by split.
    Qed.

    Lemma replaced_key_is_uniform :
      (R_kdf false ∘ KDFIdeal)%pack ≈₀ (R_kdf true ∘ KDFIdeal)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel arg.
      destruct arg as [k_auth aux].
      simplify_linking.
      ssprove_swap_lhs 0%N.
      do 8 (eapply r_uniform_bij; [exact: id_bijective | move=> ? /=]).
      apply: r_ret => s0 s1 ->. by split.
    Qed.

    Theorem session_hops b :
      ∀ LA A,
        ValidPackage LA I_session A_export A →
        AdvantageE (Session b) (R_kdf b ∘ KDFIdeal)%pack A
        <= AdvantageE MasksHideOverflow OverflowUniform (A ∘ R_masks b)%pack
           + AdvantageE KEMReal KEMIdeal (A ∘ R_kem b)%pack
           + AdvantageE KDFReal KDFIdeal (A ∘ R_kdf b)%pack.
    Proof.
      move=> LA A VA.
      ssprove triangle (Session b) [::
        (R_masks b ∘ MasksHideOverflow)%pack ;
        (R_masks b ∘ OverflowUniform)%pack ;
        (R_kem b ∘ KEMReal)%pack ;
        (R_kem b ∘ KEMIdeal)%pack ;
        (R_kdf b ∘ KDFReal)%pack
      ] (R_kdf b ∘ KDFIdeal)%pack A as ineq.
      eapply Order.POrderTheory.le_trans; first exact: ineq.
      erewrite (session_is_masks_reduction b LA A VA); try fmap_solve.
      erewrite (uniform_overflow_is_kem_reduction b LA A VA); try fmap_solve.
      erewrite (ideal_kem_is_kdf_reduction b LA A VA); try fmap_solve.
      by rewrite GRing.add0r !GRing.addr0 !Advantage_link.
    Qed.

    Theorem session_key_secrecy :
      ∀ LA A,
        ValidPackage LA I_session A_export A →
        AdvantageE SessionReal SessionIdeal A
        <= (AdvantageE MasksHideOverflow OverflowUniform (A ∘ R_masks false)%pack
            + AdvantageE KEMReal KEMIdeal (A ∘ R_kem false)%pack
            + AdvantageE KDFReal KDFIdeal (A ∘ R_kdf false)%pack)
           + (AdvantageE MasksHideOverflow OverflowUniform (A ∘ R_masks true)%pack
              + AdvantageE KEMReal KEMIdeal (A ∘ R_kem true)%pack
              + AdvantageE KDFReal KDFIdeal (A ∘ R_kdf true)%pack).
    Proof.
      move=> LA A VA.
      ssprove triangle SessionReal [::
        (Session false : raw_package) ;
        (R_kdf false ∘ KDFIdeal)%pack ;
        (R_kdf true ∘ KDFIdeal)%pack
      ] SessionIdeal A as ineq.
      eapply Order.POrderTheory.le_trans; first exact: ineq.
      erewrite (real_is_session_false LA A VA); try fmap_solve.
      erewrite (replaced_key_is_uniform LA A VA); try fmap_solve.
      rewrite GRing.add0r GRing.addr0 [AdvantageE _ SessionIdeal _]Advantage_sym.
      apply: Num.Theory.lerD.
      - exact: session_hops VA.
      - exact: session_hops VA.
    Qed.

    Definition MasksHideOverflowIdealG : package emptym I_masked_encaps :=
      [package emptym ;
        #def #[ ENCAPS ] (_ : 'unit) : 'ch(MaskedEncaps_t) {
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          K ← sample uniform (2 ^ key_bits) ;;
          theta ← sample uniform (2 ^ seed_bits) ;;
          let pk := keygen kc in
          ret (encaps_with pk msg salt K theta, masked_overflow pk msg theta)
        }
      ].

    Definition OverflowUniformIdealG : package emptym I_masked_encaps :=
      [package emptym ;
        #def #[ ENCAPS ] (_ : 'unit) : 'ch(MaskedEncaps_t) {
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          K ← sample uniform (2 ^ key_bits) ;;
          theta ← sample uniform (2 ^ seed_bits) ;;
          a ← sample uniform (2 ^ mu_bits) ;;
          t ← sample uniform (2 ^ tau_bits) ;;
          ret (encaps_with (keygen kc) msg salt K theta, (a, t))
        }
      ].

    Definition R_seed : package I_derive I_masked_encaps :=
      [package emptym ;
        #def #[ ENCAPS ] (_ : 'unit) : 'ch(MaskedEncaps_t) {
          #import {sig #[ DERIVE ] : 'unit → 'ch(Derived_t)} as derive ;;
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          K ← sample uniform (2 ^ key_bits) ;;
          d ← derive Datatypes.tt ;;
          let '(coins, (mu, tau)) := d in
          let pk := keygen kc in
          let Pc := unreduced_v pk.2 msg coins in
          ret ((pk, ((hqc_ciphertext (hqc_pk pk) msg coins, salt), K)),
               (f_mu Pc mu, f_tau Pc tau))
        }
      ].

    Lemma seed_masks_hide_overflow :
      MasksHideOverflowIdealG
      ≈₀ (R_seed ∘ MasksFromSeed seed_bits coins_of_seed mu_of_seed tau_of_seed)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel arg.
      simplify_linking.
      do 5 (eapply r_uniform_bij; [exact: id_bijective | move=> ? /=]).
      apply: r_ret => s0 s1 ->. by split.
    Qed.

    Lemma independent_masks_uniform_overflow :
      (R_seed ∘ MasksIndependentOfSeed seed_bits coins_of_seed)%pack
      ≈₀ OverflowUniformIdealG.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel arg.
      simplify_linking.
      eapply r_uniform_bij; first exact: id_bijective. move=> kc /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> msg /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> salt /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> K /=.
      eapply r_uniform_bij; first exact: id_bijective. move=> theta /=.
      pose Pc := unreduced_v (keygen kc).2 msg (coins_of_seed theta).
      eapply r_uniform_bij.
      Unshelve. 3: exact (f_mu Pc).
      { apply: f_mu_bij. }
      move=> mu /=.
      eapply r_uniform_bij.
      Unshelve. 3: exact (f_tau Pc).
      { apply: f_tau_bij. }
      move=> tau /=.
      apply: r_ret => s0 s1 ->. by split.
    Qed.

    Theorem overflow_masks_from_seed_masks :
      ∀ LB B,
        ValidPackage LB I_masked_encaps A_export B →
        AdvantageE MasksHideOverflowIdealG OverflowUniformIdealG B
        <= AdvantageE (MasksFromSeed seed_bits coins_of_seed mu_of_seed tau_of_seed)
             (MasksIndependentOfSeed seed_bits coins_of_seed) (B ∘ R_seed)%pack.
    Proof.
      move=> LB B VB.
      ssprove triangle MasksHideOverflowIdealG [::
        (R_seed ∘ MasksFromSeed seed_bits coins_of_seed mu_of_seed tau_of_seed)%pack ;
        (R_seed ∘ MasksIndependentOfSeed seed_bits coins_of_seed)%pack
      ] OverflowUniformIdealG B as ineq.
      eapply Order.POrderTheory.le_trans; first exact: ineq.
      erewrite (seed_masks_hide_overflow LB B VB); try fmap_solve.
      erewrite (independent_masks_uniform_overflow LB B VB); try fmap_solve.
      by rewrite GRing.add0r GRing.addr0 Advantage_link.
    Qed.

  End SessionKey.

End HQCLetheSession.

Module HQCLetheSessionFor (H : HQCParams) (M : CRTModuli H).
  Module Params <: HQCLetheParams.
    Include H.
    Include M.
  End Params.
  Include HQCLetheSession Params.
End HQCLetheSessionFor.

Module HQCLetheSession1 (E : HQC1Encoding) (M : CRTModuli HQC1Consts).
  Module Base := HQC1 E.
  Include HQCLetheSessionFor Base M.
End HQCLetheSession1.
Module HQCLetheSession3 (E : HQC3Encoding) (M : CRTModuli HQC3Consts).
  Module Base := HQC3 E.
  Include HQCLetheSessionFor Base M.
End HQCLetheSession3.
Module HQCLetheSession5 (E : HQC5Encoding) (M : CRTModuli HQC5Consts).
  Module Base := HQC5 E.
  Include HQCLetheSessionFor Base M.
End HQCLetheSession5.
