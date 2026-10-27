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
From SSProve.Crypt Require Import TotalProbability HybridArgument.
Import PackageNotation.
#[local] Open Scope package_scope.
#[local] Open Scope ring_scope.

From SSProveHQC Require Import Tuple HQC HQCLethe DerivedMasks SessionKey Hybrid.

Module HQCLetheSessionHybrid (P : HQCLetheParams).
  Include HQCLetheSession P.
  Import HQC_Sec.

  Section Instances.

    Context (seed_bits : nat).
    Context (coins_of_seed : 'I_(2 ^ seed_bits) -> Coins_t).
    Context (mu_of_seed : 'I_(2 ^ seed_bits) -> MuMask_t).
    Context (tau_of_seed : 'I_(2 ^ seed_bits) -> TauMask_t).

    Context (hseed_bits keygen_bits salt_bits key_bits : nat).
    Context (auth_bits session_bits transcript_bits : nat).
    Context (Aux_t Tag_t : choice_type).

    #[local] Notation HSeed := (HSeed_t hseed_bits).
    #[local] Notation ClientPK := (ClientPK_t hseed_bits).
    #[local] Notation Salt := (Salt_t salt_bits).
    #[local] Notation Key := (Key_t key_bits).
    #[local] Notation AuthKey := (AuthKey_t auth_bits).
    #[local] Notation Seed := (Seed_t seed_bits).
    #[local] Notation KdfOut := (KdfOut_t session_bits transcript_bits).

    Context (h_of_seed : HSeed -> Rq_ct).
    Context (keygen : 'I_(2 ^ keygen_bits) -> ClientPK).
    Context (fo_derive : ClientPK -> Message_t -> Salt -> Key * Seed).
    Context (kdf : Key -> AuthKey -> KdfOut).
    Context (confirm : TranscriptKey_t transcript_bits -> ClientPK -> Salt -> Aux_t -> Tag_t).
    #[local] Notation Encaps := (Encaps_t hseed_bits salt_bits key_bits).

    #[local] Notation encaps_of :=
      (encaps_of seed_bits coins_of_seed hseed_bits salt_bits key_bits h_of_seed fo_derive).
    #[local] Notation masked_overflow :=
      (masked_overflow seed_bits coins_of_seed mu_of_seed tau_of_seed hseed_bits).
    #[local] Notation MaskedEncaps := (MaskedEncaps_t hseed_bits salt_bits key_bits).
    #[local] Notation SArg := (SessionArg_t auth_bits Aux_t).
    #[local] Notation SView := (View_t hseed_bits salt_bits session_bits Tag_t).

    #[local] Notation G1Real :=
      (SessionReal seed_bits coins_of_seed mu_of_seed tau_of_seed hseed_bits keygen_bits
         salt_bits key_bits auth_bits session_bits transcript_bits Aux_t Tag_t
         h_of_seed keygen fo_derive kdf confirm).
    #[local] Notation G1Ideal :=
      (SessionIdeal seed_bits coins_of_seed mu_of_seed tau_of_seed hseed_bits keygen_bits
         salt_bits key_bits auth_bits session_bits transcript_bits Aux_t Tag_t
         h_of_seed keygen fo_derive kdf confirm).
    #[local] Notation G1MasksReal :=
      (MasksHideOverflow seed_bits coins_of_seed mu_of_seed tau_of_seed hseed_bits keygen_bits
         salt_bits key_bits h_of_seed keygen fo_derive).
    #[local] Notation G1MasksIdeal :=
      (OverflowUniform seed_bits coins_of_seed hseed_bits keygen_bits salt_bits key_bits
         h_of_seed keygen fo_derive).
    #[local] Notation G1KEMReal :=
      (KEMReal seed_bits coins_of_seed hseed_bits keygen_bits salt_bits key_bits
         h_of_seed keygen fo_derive).
    #[local] Notation G1KEMIdeal :=
      (KEMIdeal seed_bits coins_of_seed hseed_bits keygen_bits salt_bits key_bits
         h_of_seed keygen fo_derive).
    #[local] Notation G1KDFReal := (KDFReal key_bits auth_bits session_bits transcript_bits kdf).
    #[local] Notation G1KDFIdeal := (KDFIdeal auth_bits session_bits transcript_bits).
    #[local] Notation G1R_masks :=
      (R_masks hseed_bits salt_bits key_bits auth_bits session_bits transcript_bits Aux_t Tag_t
         kdf confirm).
    #[local] Notation G1R_kem :=
      (R_kem hseed_bits salt_bits key_bits auth_bits session_bits transcript_bits Aux_t Tag_t
         kdf confirm).
    #[local] Notation G1R_kdf :=
      (R_kdf seed_bits coins_of_seed hseed_bits keygen_bits salt_bits key_bits auth_bits
         session_bits transcript_bits Aux_t Tag_t h_of_seed keygen fo_derive confirm).

    Definition kem_real (_ : 'unit) : dist Encaps :=
      {code
        kc ← sample uniform (2 ^ keygen_bits) ;;
        msg ← sample uniform (2 ^ k) ;;
        salt ← sample uniform (2 ^ salt_bits) ;;
        ret (encaps_of (keygen kc) msg salt)
      }.

    Definition kem_ideal (_ : 'unit) : dist Encaps :=
      {code
        K' ← sample uniform (2 ^ key_bits) ;;
        kc ← sample uniform (2 ^ keygen_bits) ;;
        msg ← sample uniform (2 ^ k) ;;
        salt ← sample uniform (2 ^ salt_bits) ;;
        let e := encaps_of (keygen kc) msg salt in
        ret (e.1, (e.2.1, K'))
      }.

    Definition masks_real (_ : 'unit) : dist MaskedEncaps :=
      {code
        kc ← sample uniform (2 ^ keygen_bits) ;;
        msg ← sample uniform (2 ^ k) ;;
        salt ← sample uniform (2 ^ salt_bits) ;;
        let pk := keygen kc in
        ret (encaps_of pk msg salt, masked_overflow pk msg (fo_derive pk msg salt).2)
      }.

    Definition masks_ideal (_ : 'unit) : dist MaskedEncaps :=
      {code
        kc ← sample uniform (2 ^ keygen_bits) ;;
        msg ← sample uniform (2 ^ k) ;;
        salt ← sample uniform (2 ^ salt_bits) ;;
        a ← sample uniform (2 ^ mu_bits) ;;
        t ← sample uniform (2 ^ tau_bits) ;;
        ret (encaps_of (keygen kc) msg salt, (a, t))
      }.

    Definition kdf_real (k_auth : AuthKey) : dist KdfOut :=
      {code
        K ← sample uniform (2 ^ key_bits) ;;
        ret (kdf K k_auth)
      }.

    Definition kdf_ideal (_ : AuthKey) : dist KdfOut :=
      {code
        ks ← sample uniform (2 ^ session_bits) ;;
        kt ← sample uniform (2 ^ transcript_bits) ;;
        ret (ks, kt)
      }.

    Lemma encaps_not_pick : ENCAPS != PICK. Proof. by []. Qed.
    Lemma kdf_not_pick : KDF != PICK. Proof. by []. Qed.

    #[local] Notation KemINST := (INST ENCAPS 'unit Encaps kem_real kem_ideal).
    #[local] Notation MasksINST := (INST ENCAPS 'unit MaskedEncaps masks_real masks_ideal).
    #[local] Notation KdfINST := (INST KDF AuthKey KdfOut kdf_real kdf_ideal).
    #[local] Notation CountS := (COUNT SESSION SArg SView).
    #[local] Notation CountKem := (COUNT ENCAPS 'unit Encaps).
    #[local] Notation CountMasks := (COUNT ENCAPS 'unit MaskedEncaps).
    #[local] Notation CountKdf := (COUNT KDF AuthKey KdfOut).

    Definition HybKem q :=
      HYB_raw ENCAPS 'unit Encaps kem_real kem_ideal encaps_not_pick q.
    Definition HybMasks q :=
      HYB_raw ENCAPS 'unit MaskedEncaps masks_real masks_ideal encaps_not_pick q.
    Definition HybKdf q :=
      HYB_raw KDF AuthKey KdfOut kdf_real kdf_ideal kdf_not_pick q.

    Lemma kem_insts :
      pack G1KEMReal = pack (KemINST true) ∧ pack G1KEMIdeal = pack (KemINST false).
    Proof. by split. Qed.

    Lemma masks_insts :
      pack G1MasksReal = pack (MasksINST true) ∧ pack G1MasksIdeal = pack (MasksINST false).
    Proof. by split. Qed.

    Lemma kdf_insts :
      pack G1KDFReal = pack (KdfINST true) ∧ pack G1KDFIdeal = pack (KdfINST false).
    Proof. by split. Qed.

    Theorem kem_single_instance q LA A `{VA : ValidPackage LA (I_encaps hseed_bits salt_bits key_bits) A_export A} :
      fseparate LA [fmap count_loc] →
      fseparate LA [fmap slide_loc] →
      fseparate LA [fmap cell nat] →
      AdvantageE (CountKem q ∘ G1KEMReal)%pack (CountKem q ∘ G1KEMIdeal)%pack A
      = AdvantageE (CountKem 1 ∘ G1KEMReal)%pack (CountKem 1 ∘ G1KEMIdeal)%pack (A ∘ HybKem q)%pack
        *+ q.
    Proof.
      move=> S1 S2 S3.
      case: kem_insts => -> ->.
      exact: multi_to_single_instance.
    Qed.

    Theorem masks_single_instance q LA A
      `{VA : ValidPackage LA (I_masked_encaps hseed_bits salt_bits key_bits) A_export A} :
      fseparate LA [fmap count_loc] →
      fseparate LA [fmap slide_loc] →
      fseparate LA [fmap cell nat] →
      AdvantageE (CountMasks q ∘ G1MasksReal)%pack (CountMasks q ∘ G1MasksIdeal)%pack A
      = AdvantageE (CountMasks 1 ∘ G1MasksReal)%pack (CountMasks 1 ∘ G1MasksIdeal)%pack
          (A ∘ HybMasks q)%pack *+ q.
    Proof.
      move=> S1 S2 S3.
      case: masks_insts => -> ->.
      exact: multi_to_single_instance.
    Qed.

    Theorem kdf_single_instance q LA A
      `{VA : ValidPackage LA (I_kdf auth_bits session_bits transcript_bits) A_export A} :
      fseparate LA [fmap count_loc] →
      fseparate LA [fmap slide_loc] →
      fseparate LA [fmap cell nat] →
      AdvantageE (CountKdf q ∘ G1KDFReal)%pack (CountKdf q ∘ G1KDFIdeal)%pack A
      = AdvantageE (CountKdf 1 ∘ G1KDFReal)%pack (CountKdf 1 ∘ G1KDFIdeal)%pack
          (A ∘ HybKdf q)%pack *+ q.
    Proof.
      move=> S1 S2 S3.
      case: kdf_insts => -> ->.
      exact: multi_to_single_instance.
    Qed.

    Ltac commute_count x :=
      eapply eq_rel_perf_ind_eq;
      simplify_eq_rel x;
      destruct x as [? ?];
      simplify_linking;
      ssprove_code_simpl;
      ssprove_code_simpl_more;
      ssprove_swap_rhs 0%N;
      ssprove_sync_eq => ?;
      ssprove_swap_rhs 0%N;
      ssprove_sync => ?;
      ssprove_swap_rhs 0%N;
      ssprove_sync_eq;
      eapply rpost_weaken_rule;
      [ apply rreflexivity_rule | by move=> [? ?] [? ?] [-> ->] ].

    Lemma count_commutes_kem_real q b :
      (CountS q ∘ (G1R_kem b ∘ G1KEMReal))%pack ≈₀ (G1R_kem b ∘ (CountKem q ∘ G1KEMReal))%pack.
    Proof. commute_count arg. Qed.

    Lemma count_commutes_kem_ideal q b :
      (CountS q ∘ (G1R_kem b ∘ G1KEMIdeal))%pack ≈₀ (G1R_kem b ∘ (CountKem q ∘ G1KEMIdeal))%pack.
    Proof. commute_count arg. Qed.

    Lemma count_commutes_masks_real q b :
      (CountS q ∘ (G1R_masks b ∘ G1MasksReal))%pack
      ≈₀ (G1R_masks b ∘ (CountMasks q ∘ G1MasksReal))%pack.
    Proof. commute_count arg. Qed.

    Lemma count_commutes_masks_ideal q b :
      (CountS q ∘ (G1R_masks b ∘ G1MasksIdeal))%pack
      ≈₀ (G1R_masks b ∘ (CountMasks q ∘ G1MasksIdeal))%pack.
    Proof. commute_count arg. Qed.

    Lemma count_commutes_kdf_real q b :
      (CountS q ∘ (G1R_kdf b ∘ G1KDFReal))%pack ≈₀ (G1R_kdf b ∘ (CountKdf q ∘ G1KDFReal))%pack.
    Proof. commute_count arg. Qed.

    Lemma count_commutes_kdf_ideal q b :
      (CountS q ∘ (G1R_kdf b ∘ G1KDFIdeal))%pack ≈₀ (G1R_kdf b ∘ (CountKdf q ∘ G1KDFIdeal))%pack.
    Proof. commute_count arg. Qed.

    Lemma AdvantageE_perfect_both (X X' Y Y' A : raw_package) :
      AdvantageE X X' A = 0 → AdvantageE Y Y' A = 0 →
      AdvantageE X Y A = AdvantageE X' Y' A.
    Proof.
      rewrite /AdvantageE => /Num.Theory.normr0_eq0/subr0_eq EX /Num.Theory.normr0_eq0/subr0_eq EY.
      by rewrite EX EY.
    Qed.

    Ltac solve_sep :=
      lazymatch goal with |- fseparate _ _ => idtac end;
      first
        [ assumption
        | exact: fseparatem0
        | exact: fseparate0m
        | apply: fseparateUr; solve_sep
        | apply: fseparateUl; solve_sep ].

    Lemma kem_term q b LA A `{VA : ValidPackage LA (I_session hseed_bits salt_bits auth_bits session_bits Aux_t Tag_t) A_export A} :
      fseparate LA [fmap count_loc] →
      fseparate LA [fmap slide_loc] →
      fseparate LA [fmap cell nat] →
      AdvantageE G1KEMReal G1KEMIdeal ((A ∘ CountS q) ∘ G1R_kem b)%pack
      = AdvantageE (CountKem 1 ∘ G1KEMReal)%pack (CountKem 1 ∘ G1KEMIdeal)%pack
          ((A ∘ G1R_kem b) ∘ HybKem q)%pack *+ q.
    Proof.
      move=> S1 S2 S3.
      rewrite (Advantage_link G1KEMReal G1KEMIdeal (A ∘ CountS q)%pack (G1R_kem b)).
      rewrite (Advantage_link (G1R_kem b ∘ G1KEMReal)%pack (G1R_kem b ∘ G1KEMIdeal)%pack A (CountS q)).
      rewrite (AdvantageE_perfect_both _ (G1R_kem b ∘ (CountKem q ∘ G1KEMReal))%pack
                 _ (G1R_kem b ∘ (CountKem q ∘ G1KEMIdeal))%pack A).
      1: apply: (count_commutes_kem_real q b LA A VA); solve_sep.
      1: apply: (count_commutes_kem_ideal q b LA A VA); solve_sep.
      rewrite -(Advantage_link (CountKem q ∘ G1KEMReal)%pack (CountKem q ∘ G1KEMIdeal)%pack A (G1R_kem b)).
      have VAR : ValidPackage (unionm LA emptym) (I_encaps hseed_bits salt_bits key_bits) A_export
                   (A ∘ G1R_kem b)%pack by exact _.
      apply: (kem_single_instance q _ _); solve_sep.
    Qed.

    Lemma masks_term q b LA A `{VA : ValidPackage LA (I_session hseed_bits salt_bits auth_bits session_bits Aux_t Tag_t) A_export A} :
      fseparate LA [fmap count_loc] →
      fseparate LA [fmap slide_loc] →
      fseparate LA [fmap cell nat] →
      AdvantageE G1MasksReal G1MasksIdeal ((A ∘ CountS q) ∘ G1R_masks b)%pack
      = AdvantageE (CountMasks 1 ∘ G1MasksReal)%pack (CountMasks 1 ∘ G1MasksIdeal)%pack
          ((A ∘ G1R_masks b) ∘ HybMasks q)%pack *+ q.
    Proof.
      move=> S1 S2 S3.
      rewrite (Advantage_link G1MasksReal G1MasksIdeal (A ∘ CountS q)%pack (G1R_masks b)).
      rewrite (Advantage_link (G1R_masks b ∘ G1MasksReal)%pack (G1R_masks b ∘ G1MasksIdeal)%pack A (CountS q)).
      rewrite (AdvantageE_perfect_both _ (G1R_masks b ∘ (CountMasks q ∘ G1MasksReal))%pack
                 _ (G1R_masks b ∘ (CountMasks q ∘ G1MasksIdeal))%pack A).
      1: apply: (count_commutes_masks_real q b LA A VA); solve_sep.
      1: apply: (count_commutes_masks_ideal q b LA A VA); solve_sep.
      rewrite -(Advantage_link (CountMasks q ∘ G1MasksReal)%pack (CountMasks q ∘ G1MasksIdeal)%pack A (G1R_masks b)).
      have VAR : ValidPackage (unionm LA emptym) (I_masked_encaps hseed_bits salt_bits key_bits) A_export
                   (A ∘ G1R_masks b)%pack by exact _.
      apply: (masks_single_instance q _ _); solve_sep.
    Qed.

    Lemma kdf_term q b LA A `{VA : ValidPackage LA (I_session hseed_bits salt_bits auth_bits session_bits Aux_t Tag_t) A_export A} :
      fseparate LA [fmap count_loc] →
      fseparate LA [fmap slide_loc] →
      fseparate LA [fmap cell nat] →
      AdvantageE G1KDFReal G1KDFIdeal ((A ∘ CountS q) ∘ G1R_kdf b)%pack
      = AdvantageE (CountKdf 1 ∘ G1KDFReal)%pack (CountKdf 1 ∘ G1KDFIdeal)%pack
          ((A ∘ G1R_kdf b) ∘ HybKdf q)%pack *+ q.
    Proof.
      move=> S1 S2 S3.
      rewrite (Advantage_link G1KDFReal G1KDFIdeal (A ∘ CountS q)%pack (G1R_kdf b)).
      rewrite (Advantage_link (G1R_kdf b ∘ G1KDFReal)%pack (G1R_kdf b ∘ G1KDFIdeal)%pack A (CountS q)).
      rewrite (AdvantageE_perfect_both _ (G1R_kdf b ∘ (CountKdf q ∘ G1KDFReal))%pack
                 _ (G1R_kdf b ∘ (CountKdf q ∘ G1KDFIdeal))%pack A).
      1: apply: (count_commutes_kdf_real q b LA A VA); solve_sep.
      1: apply: (count_commutes_kdf_ideal q b LA A VA); solve_sep.
      rewrite -(Advantage_link (CountKdf q ∘ G1KDFReal)%pack (CountKdf q ∘ G1KDFIdeal)%pack A (G1R_kdf b)).
      have VAR : ValidPackage (unionm LA emptym) (I_kdf auth_bits session_bits transcript_bits) A_export
                   (A ∘ G1R_kdf b)%pack by exact _.
      apply: (kdf_single_instance q _ _); solve_sep.
    Qed.

    Theorem session_key_secrecy_single_instance q LA A
      `{VA : ValidPackage LA (I_session hseed_bits salt_bits auth_bits session_bits Aux_t Tag_t) A_export A} :
      fseparate LA [fmap count_loc] →
      fseparate LA [fmap slide_loc] →
      fseparate LA [fmap cell nat] →
      AdvantageE (CountS q ∘ G1Real)%pack (CountS q ∘ G1Ideal)%pack A
      <= (AdvantageE (CountMasks 1 ∘ G1MasksReal)%pack (CountMasks 1 ∘ G1MasksIdeal)%pack
            ((A ∘ G1R_masks false) ∘ HybMasks q)%pack *+ q
          + AdvantageE (CountKem 1 ∘ G1KEMReal)%pack (CountKem 1 ∘ G1KEMIdeal)%pack
              ((A ∘ G1R_kem false) ∘ HybKem q)%pack *+ q
          + AdvantageE (CountKdf 1 ∘ G1KDFReal)%pack (CountKdf 1 ∘ G1KDFIdeal)%pack
              ((A ∘ G1R_kdf false) ∘ HybKdf q)%pack *+ q)
         + (AdvantageE (CountMasks 1 ∘ G1MasksReal)%pack (CountMasks 1 ∘ G1MasksIdeal)%pack
              ((A ∘ G1R_masks true) ∘ HybMasks q)%pack *+ q
            + AdvantageE (CountKem 1 ∘ G1KEMReal)%pack (CountKem 1 ∘ G1KEMIdeal)%pack
                ((A ∘ G1R_kem true) ∘ HybKem q)%pack *+ q
            + AdvantageE (CountKdf 1 ∘ G1KDFReal)%pack (CountKdf 1 ∘ G1KDFIdeal)%pack
                ((A ∘ G1R_kdf true) ∘ HybKdf q)%pack *+ q).
    Proof.
      move=> S1 S2 S3.
      rewrite -(Advantage_link G1Real G1Ideal A (CountS q)).
      have VAC : ValidPackage (unionm LA [fmap count_loc])
                   (I_session hseed_bits salt_bits auth_bits session_bits Aux_t Tag_t) A_export
                   (A ∘ CountS q)%pack by exact _.
      have H := session_key_secrecy seed_bits coins_of_seed mu_of_seed tau_of_seed hseed_bits
                  keygen_bits salt_bits key_bits auth_bits session_bits transcript_bits Aux_t Tag_t
                  h_of_seed keygen fo_derive kdf confirm _ _ VAC.
      by rewrite !masks_term // !kem_term // !kdf_term // in H.
    Qed.

  End Instances.
End HQCLetheSessionHybrid.

Module HQCLetheSessionHybridFor (H : HQCParams) (M : CRTModuli H).
  Module Params <: HQCLetheParams.
    Include H.
    Include M.
  End Params.
  Include HQCLetheSessionHybrid Params.
End HQCLetheSessionHybridFor.

Module HQCLetheSessionHybrid1 (E : HQC1Encoding) (M : CRTModuli HQC1Consts).
  Module Base := HQC1 E.
  Include HQCLetheSessionHybridFor Base M.
End HQCLetheSessionHybrid1.
Module HQCLetheSessionHybrid3 (E : HQC3Encoding) (M : CRTModuli HQC3Consts).
  Module Base := HQC3 E.
  Include HQCLetheSessionHybridFor Base M.
End HQCLetheSessionHybrid3.
Module HQCLetheSessionHybrid5 (E : HQC5Encoding) (M : CRTModuli HQC5Consts).
  Module Base := HQC5 E.
  Include HQCLetheSessionHybridFor Base M.
End HQCLetheSessionHybrid5.
