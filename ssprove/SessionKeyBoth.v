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
From SSProve.Crypt Require Import TotalProbability.
Import PackageNotation.
#[local] Open Scope package_scope.
#[local] Open Scope ring_scope.

From SSProveHQC Require Import Tuple HQC HQCLethe DerivedMasks SessionKey Hybrid.

Lemma sum4_regroup (R : zmodType) (a b c d : R) : a + b + c + d = (a + d) + (b + c).
Proof. by rewrite -!addrA; congr (_ + _); rewrite [c + d]addrC addrCA. Qed.

Module HQCLetheBoth (P : HQCLetheParams).
  Include HQCLetheSession P.
  Import HQC_Sec.

  Section MLKEMSide.

    Context (seed_bits : nat).
    Context (coins_of_seed : 'I_(2 ^ seed_bits) -> Coins_t).
    Context (mu_of_seed : 'I_(2 ^ seed_bits) -> MuMask_t).
    Context (tau_of_seed : 'I_(2 ^ seed_bits) -> TauMask_t).

    Context (hseed_bits keygen_bits salt_bits key_bits : nat).
    Context (auth_bits session_bits transcript_bits : nat).
    Context (Tag_t : choice_type).

    Context (mlkem_key_bits mlkem_coin_bits : nat).
    Context (McPK_t McCt_t : choice_type).
    Context (cookie_key_bits cookie_nonce_bits cookie_bits chan_bits : nat).

    #[local] Notation HSeed := (HSeed_t hseed_bits).
    #[local] Notation ClientPK := (ClientPK_t hseed_bits).
    #[local] Notation Salt := (Salt_t salt_bits).
    #[local] Notation Key := (Key_t key_bits).
    #[local] Notation AuthKey := (AuthKey_t auth_bits).
    #[local] Notation SessionKey := (SessionKey_t session_bits).
    #[local] Notation TranscriptKey := (TranscriptKey_t transcript_bits).
    #[local] Notation Seed := (Seed_t seed_bits).
    #[local] Notation KdfOut := (KdfOut_t session_bits transcript_bits).

    Definition CookieKey_t := chFin (2 ^ cookie_key_bits).
    Definition Cookie_t := chFin (2 ^ cookie_bits).
    Definition ChanKeys_t := chFin (2 ^ chan_bits).
    Definition CookiePlain_t := chProd Seed (chProd Message_t (chProd HSeed AuthKey)).
    Definition HqcSide_t := chProd ClientPK (chProd Message_t Salt).
    Definition MlkemEncaps_t := chProd McPK_t (chProd McCt_t AuthKey).
    Definition AuthDerived_t := chProd KdfOut ChanKeys_t.
    Definition ViewM_t :=
      chProd McPK_t (chProd McCt_t (chProd Cookie_t
        (chProd ChanKeys_t (chProd Tag_t SessionKey)))).

    Context (fo_derive : ClientPK -> Message_t -> Salt -> Key * Seed).
    Context (kdf : Key -> AuthKey -> KdfOut).
    Context (confirm : TranscriptKey -> ClientPK -> Salt -> McCt_t -> Tag_t).
    Context (mlkem_keygen : 'I_(2 ^ mlkem_key_bits) -> McPK_t).
    Context (mlkem_encaps : McPK_t -> 'I_(2 ^ mlkem_coin_bits) -> McCt_t * AuthKey).
    Context (seal_cookie : CookieKey_t -> CookiePlain_t -> 'I_(2 ^ cookie_nonce_bits) -> Cookie_t).
    Context (chan_keys : AuthKey -> ChanKeys_t).
    Context (h_of_seed : HSeed -> Rq_ct).
    Context (keygen : 'I_(2 ^ keygen_bits) -> ClientPK).
    Context (wire_coin_bits : nat) (Wire_t : choice_type).

    Definition mlkem_loc : Location := mkloc 30 (None : 'option McPK_t).
    Definition cookie_loc : Location := mkloc 31 (None : 'option CookieKey_t).

    Definition cookie_plain (theta : Seed) (msg : Message_t) (pk : ClientPK) (k_auth : AuthKey)
      : CookiePlain_t :=
      (theta, (msg, (pk.1, k_auth))).

    Definition view_m (mpk : McPK_t) (c : McCt_t) (cookie : Cookie_t) (ch : ChanKeys_t)
      (keys : KdfOut) (pk : ClientPK) (salt : Salt) (ks_out : SessionKey) : ViewM_t :=
      (mpk, (c, (cookie, (ch, (confirm keys.2 pk salt c, ks_out))))).

    Definition SESSION_M : ident := 7%N.
    Definition MLKEM : ident := 8%N.
    Definition COOKIE : ident := 9%N.
    Definition AUTHKDF : ident := 10%N.

    Definition I_session_m : Interface :=
      [interface #val #[ SESSION_M ] : 'ch(HqcSide_t) → 'ch(ViewM_t) ].
    Definition I_mlkem : Interface :=
      [interface #val #[ MLKEM ] : 'unit → 'ch(MlkemEncaps_t) ].
    Definition I_cookie : Interface :=
      [interface #val #[ COOKIE ] : 'ch(CookiePlain_t) → 'ch(Cookie_t) ].
    Definition I_authkdf : Interface :=
      [interface #val #[ AUTHKDF ] : 'ch(Key) → 'ch(AuthDerived_t) ].

    Definition SessionM (replace : bool) : package emptym I_session_m :=
      [package [fmap mlkem_loc ; cookie_loc] ;
        #def #[ SESSION_M ] (hq : 'ch(HqcSide_t)) : 'ch(ViewM_t) {
          let '(pk, (msg, salt)) := hq in
          mk ← get mlkem_loc ;;
          mpk ← (match mk with
                 | Some p => ret p
                 | None => kr ← sample uniform (2 ^ mlkem_key_bits) ;;
                           #put mlkem_loc := Some (mlkem_keygen kr) ;;
                           ret (mlkem_keygen kr)
                 end) ;;
          r ← sample uniform (2 ^ mlkem_coin_bits) ;;
          fresh ← sample uniform (2 ^ session_bits) ;;
          kk ← get cookie_loc ;;
          ck ← (match kk with
                | Some k => ret k
                | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                          #put cookie_loc := Some k ;;
                          ret k
                end) ;;
          n ← sample uniform (2 ^ cookie_nonce_bits) ;;
          let '(c, k_auth) := mlkem_encaps mpk r in
          let '(K, theta) := fo_derive pk msg salt in
          let keys := kdf K k_auth in
          ret (view_m mpk c (seal_cookie ck (cookie_plain theta msg pk k_auth) n)
                 (chan_keys k_auth) keys pk salt (exported_key session_bits transcript_bits replace keys fresh))
        }
      ].

    Definition MlkemReal : package emptym I_mlkem :=
      [package [fmap mlkem_loc] ;
        #def #[ MLKEM ] (_ : 'unit) : 'ch(MlkemEncaps_t) {
          mk ← get mlkem_loc ;;
          mpk ← (match mk with
                 | Some p => ret p
                 | None => kr ← sample uniform (2 ^ mlkem_key_bits) ;;
                           #put mlkem_loc := Some (mlkem_keygen kr) ;;
                           ret (mlkem_keygen kr)
                 end) ;;
          r ← sample uniform (2 ^ mlkem_coin_bits) ;;
          ret (mpk, mlkem_encaps mpk r)
        }
      ].

    Definition MlkemIdeal : package emptym I_mlkem :=
      [package [fmap mlkem_loc] ;
        #def #[ MLKEM ] (_ : 'unit) : 'ch(MlkemEncaps_t) {
          mk ← get mlkem_loc ;;
          mpk ← (match mk with
                 | Some p => ret p
                 | None => kr ← sample uniform (2 ^ mlkem_key_bits) ;;
                           #put mlkem_loc := Some (mlkem_keygen kr) ;;
                           ret (mlkem_keygen kr)
                 end) ;;
          r ← sample uniform (2 ^ mlkem_coin_bits) ;;
          k' ← sample uniform (2 ^ auth_bits) ;;
          ret (mpk, ((mlkem_encaps mpk r).1, k'))
        }
      ].

    Definition CookieReal : package emptym I_cookie :=
      [package [fmap cookie_loc] ;
        #def #[ COOKIE ] (pt : 'ch(CookiePlain_t)) : 'ch(Cookie_t) {
          kk ← get cookie_loc ;;
          ck ← (match kk with
                | Some k => ret k
                | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                          #put cookie_loc := Some k ;;
                          ret k
                end) ;;
          n ← sample uniform (2 ^ cookie_nonce_bits) ;;
          ret (seal_cookie ck pt n)
        }
      ].

    Definition CookieIdeal : package emptym I_cookie :=
      [package emptym ;
        #def #[ COOKIE ] (_ : 'ch(CookiePlain_t)) : 'ch(Cookie_t) {
          c ← sample uniform (2 ^ cookie_bits) ;;
          ret c
        }
      ].

    Definition AuthKdfReal : package emptym I_authkdf :=
      [package emptym ;
        #def #[ AUTHKDF ] (K : 'ch(Key)) : 'ch(AuthDerived_t) {
          k_auth ← sample uniform (2 ^ auth_bits) ;;
          ret (kdf K k_auth, chan_keys k_auth)
        }
      ].

    Definition AuthKdfIdeal : package emptym I_authkdf :=
      [package emptym ;
        #def #[ AUTHKDF ] (_ : 'ch(Key)) : 'ch(AuthDerived_t) {
          ch ← sample uniform (2 ^ chan_bits) ;;
          kt ← sample uniform (2 ^ transcript_bits) ;;
          ks ← sample uniform (2 ^ session_bits) ;;
          ret ((ks, kt), ch)
        }
      ].

    Definition R_mlkem (replace : bool) : package I_mlkem I_session_m :=
      [package [fmap cookie_loc] ;
        #def #[ SESSION_M ] (hq : 'ch(HqcSide_t)) : 'ch(ViewM_t) {
          #import {sig #[ MLKEM ] : 'unit → 'ch(MlkemEncaps_t)} as encaps ;;
          let '(pk, (msg, salt)) := hq in
          d ← encaps Datatypes.tt ;;
          fresh ← sample uniform (2 ^ session_bits) ;;
          kk ← get cookie_loc ;;
          ck ← (match kk with
                | Some k => ret k
                | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                          #put cookie_loc := Some k ;;
                          ret k
                end) ;;
          n ← sample uniform (2 ^ cookie_nonce_bits) ;;
          let '(mpk, (c, k_auth)) := d in
          let '(K, theta) := fo_derive pk msg salt in
          let keys := kdf K k_auth in
          ret (view_m mpk c (seal_cookie ck (cookie_plain theta msg pk k_auth) n)
                 (chan_keys k_auth) keys pk salt
                 (exported_key session_bits transcript_bits replace keys fresh))
        }
      ].

    Definition R_cookie (replace : bool) : package I_cookie I_session_m :=
      [package [fmap mlkem_loc] ;
        #def #[ SESSION_M ] (hq : 'ch(HqcSide_t)) : 'ch(ViewM_t) {
          #import {sig #[ COOKIE ] : 'ch(CookiePlain_t) → 'ch(Cookie_t)} as seal ;;
          let '(pk, (msg, salt)) := hq in
          mk ← get mlkem_loc ;;
          mpk ← (match mk with
                 | Some p => ret p
                 | None => kr ← sample uniform (2 ^ mlkem_key_bits) ;;
                           #put mlkem_loc := Some (mlkem_keygen kr) ;;
                           ret (mlkem_keygen kr)
                 end) ;;
          r ← sample uniform (2 ^ mlkem_coin_bits) ;;
          k_auth ← sample uniform (2 ^ auth_bits) ;;
          fresh ← sample uniform (2 ^ session_bits) ;;
          let c := (mlkem_encaps mpk r).1 in
          let '(K, theta) := fo_derive pk msg salt in
          cookie ← seal (cookie_plain theta msg pk k_auth) ;;
          let keys := kdf K k_auth in
          ret (view_m mpk c cookie (chan_keys k_auth) keys pk salt
                 (exported_key session_bits transcript_bits replace keys fresh))
        }
      ].

    Definition R_authkdf (replace : bool) : package I_authkdf I_session_m :=
      [package [fmap mlkem_loc] ;
        #def #[ SESSION_M ] (hq : 'ch(HqcSide_t)) : 'ch(ViewM_t) {
          #import {sig #[ AUTHKDF ] : 'ch(Key) → 'ch(AuthDerived_t)} as derive ;;
          let '(pk, (msg, salt)) := hq in
          mk ← get mlkem_loc ;;
          mpk ← (match mk with
                 | Some p => ret p
                 | None => kr ← sample uniform (2 ^ mlkem_key_bits) ;;
                           #put mlkem_loc := Some (mlkem_keygen kr) ;;
                           ret (mlkem_keygen kr)
                 end) ;;
          r ← sample uniform (2 ^ mlkem_coin_bits) ;;
          let c := (mlkem_encaps mpk r).1 in
          let '(K, theta) := fo_derive pk msg salt in
          d ← derive K ;;
          fresh ← sample uniform (2 ^ session_bits) ;;
          cookie ← sample uniform (2 ^ cookie_bits) ;;
          let '(keys, ch) := d in
          ret (view_m mpk c cookie ch keys pk salt
                 (exported_key session_bits transcript_bits replace keys fresh))
        }
      ].

    Lemma session_m_is_mlkem_reduction b :
      SessionM b ≈₀ (R_mlkem b ∘ MlkemReal)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel hq.
      destruct hq as [pk [msg salt]].
      simplify_linking.
      ssprove_code_simpl.
      ssprove_sync_eq => mk.
      case: mk => [p|] /=.
      all: ssprove_code_simpl; ssprove_code_simpl_more.
      all: eapply rpost_weaken_rule; [apply rreflexivity_rule | by move=> [? ?] [? ?] [-> ->]].
    Qed.

    Ltac sync_lazy_init :=
      ssprove_code_simpl;
      ssprove_sync_eq => ?;
      match goal with
      | |- context [ match ?mk with Some _ => _ | None => _ end ] => case: mk => [?|] /=
      end;
      ssprove_code_simpl; ssprove_code_simpl_more.

    Ltac sync_step :=
      ssprove_code_simpl;
      first
        [ match goal with
          | |- context [ match ?mk with Some _ => _ | None => _ end ] =>
              is_var mk; case: mk => [?|] /=
          end
        | match goal with
          | |- context [ mlkem_encaps ?a ?b ] => case: (mlkem_encaps a b) => [? ?] /=
          | |- context [ fo_derive ?a ?b ?c ] => case: (fo_derive a b c) => [? ?] /=
          end
        | ssprove_sync_eq => ?
        | ssprove_sync_eq ].

    Ltac sync_all := repeat sync_step.

    Ltac close_same :=
      eapply rpost_weaken_rule; [apply rreflexivity_rule | by move=> [? ?] [? ?] [-> ->]].

    Lemma ideal_mlkem_is_cookie_reduction b :
      (R_mlkem b ∘ MlkemIdeal)%pack ≈₀ (R_cookie b ∘ CookieReal)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel hq.
      destruct hq as [pk [msg salt]].
      simplify_linking.
      case: (fo_derive pk msg salt) => K theta /=.
      sync_all.
      all: close_same.
    Qed.

    Lemma ideal_cookie_is_authkdf_reduction b :
      (R_cookie b ∘ CookieIdeal)%pack ≈₀ (R_authkdf b ∘ AuthKdfReal)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel hq.
      destruct hq as [pk [msg salt]].
      simplify_linking.
      case: (fo_derive pk msg salt) => K theta /=.
      sync_all.
      all: close_same.
    Qed.

    Lemma replaced_auth_key_is_uniform :
      (R_authkdf false ∘ AuthKdfIdeal)%pack ≈₀ (R_authkdf true ∘ AuthKdfIdeal)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel hq.
      destruct hq as [pk [msg salt]].
      simplify_linking.
      case: (fo_derive pk msg salt) => K theta /=.
      ssprove_code_simpl.
      ssprove_sync_eq => mk.
      case: mk => [p|] /=.
      - ssprove_code_simpl.
        do 3 (ssprove_sync_eq => ?).
        ssprove_swap_lhs 0%N.
        do 3 (ssprove_sync_eq => ?).
        apply: r_ret => s0 s1 ->. by split.
      - ssprove_code_simpl.
        ssprove_sync_eq => ?.
        ssprove_sync_eq.
        do 3 (ssprove_sync_eq => ?).
        ssprove_swap_lhs 0%N.
        do 3 (ssprove_sync_eq => ?).
        apply: r_ret => s0 s1 ->. by split.
    Qed.

    Lemma fseparate_pair (LA : Locations) (l1 l2 : Location) :
      fseparate LA [fmap l1] → fseparate LA [fmap l2] → fseparate LA [fmap l1 ; l2].
    Proof.
      move=> [H1] [H2]; constructor.
      move: H1 H2; rewrite !domm_set !domm0 !fsetU0 => H1 H2.
      by rewrite fdisjointC fdisjointUl !(fdisjointC _ (domm LA)) H1 H2.
    Qed.

    Ltac solve_sep :=
      lazymatch goal with |- fseparate _ _ => idtac end;
      first
        [ exact: fseparate_pair
        | exact: fseparatem0
        | assumption
        | apply: fseparateUr; solve_sep
        | fmap_solve ].

    Theorem session_m_hops b :
      ∀ LA A,
        ValidPackage LA I_session_m A_export A →
        fseparate LA [fmap mlkem_loc] →
        fseparate LA [fmap cookie_loc] →
        AdvantageE (SessionM b) (R_authkdf b ∘ AuthKdfIdeal)%pack A
        <= AdvantageE MlkemReal MlkemIdeal (A ∘ R_mlkem b)%pack
           + AdvantageE CookieReal CookieIdeal (A ∘ R_cookie b)%pack
           + AdvantageE AuthKdfReal AuthKdfIdeal (A ∘ R_authkdf b)%pack.
    Proof.
      move=> LA A VA SM SC.
      ssprove triangle (SessionM b) [::
        (R_mlkem b ∘ MlkemReal)%pack ;
        (R_mlkem b ∘ MlkemIdeal)%pack ;
        (R_cookie b ∘ CookieReal)%pack ;
        (R_cookie b ∘ CookieIdeal)%pack ;
        (R_authkdf b ∘ AuthKdfReal)%pack
      ] (R_authkdf b ∘ AuthKdfIdeal)%pack A as ineq.
      eapply Order.POrderTheory.le_trans; first exact: ineq.
      erewrite (session_m_is_mlkem_reduction b LA A VA); try fmap_solve.
      2: exact: fseparate_pair.
      erewrite (ideal_mlkem_is_cookie_reduction b LA A VA); try fmap_solve.
      erewrite (ideal_cookie_is_authkdf_reduction b LA A VA); try fmap_solve.
      by rewrite GRing.add0r !GRing.addr0 !Advantage_link.
    Qed.

    Theorem session_key_secrecy_mlkem :
      ∀ LA A,
        ValidPackage LA I_session_m A_export A →
        fseparate LA [fmap mlkem_loc] →
        fseparate LA [fmap cookie_loc] →
        AdvantageE (SessionM false) (SessionM true) A
        <= (AdvantageE MlkemReal MlkemIdeal (A ∘ R_mlkem false)%pack
            + AdvantageE CookieReal CookieIdeal (A ∘ R_cookie false)%pack
            + AdvantageE AuthKdfReal AuthKdfIdeal (A ∘ R_authkdf false)%pack)
           + (AdvantageE MlkemReal MlkemIdeal (A ∘ R_mlkem true)%pack
              + AdvantageE CookieReal CookieIdeal (A ∘ R_cookie true)%pack
              + AdvantageE AuthKdfReal AuthKdfIdeal (A ∘ R_authkdf true)%pack).
    Proof.
      move=> LA A VA SM SC.
      ssprove triangle (SessionM false) [::
        (R_authkdf false ∘ AuthKdfIdeal)%pack ;
        (R_authkdf true ∘ AuthKdfIdeal)%pack
      ] (SessionM true) A as ineq.
      eapply Order.POrderTheory.le_trans; first exact: ineq.
      erewrite (replaced_auth_key_is_uniform LA A VA); try fmap_solve.
      rewrite GRing.addr0 [AdvantageE _ (SessionM true) _]Advantage_sym.
      apply: Num.Theory.lerD.
      - exact: session_m_hops VA SM SC.
      - exact: session_m_hops VA SM SC.
    Qed.

    Definition authkdf_real (K : Key) : dist AuthDerived_t :=
      {code
        k_auth ← sample uniform (2 ^ auth_bits) ;;
        ret (kdf K k_auth, chan_keys k_auth)
      }.

    Definition authkdf_ideal (_ : Key) : dist AuthDerived_t :=
      {code
        ch ← sample uniform (2 ^ chan_bits) ;;
        kt ← sample uniform (2 ^ transcript_bits) ;;
        ks ← sample uniform (2 ^ session_bits) ;;
        ret ((ks, kt), ch)
      }.

    Lemma authkdf_not_pick : AUTHKDF != PICK. Proof. by []. Qed.

    Definition HybAuthKdf q :=
      HYB_raw AUTHKDF Key AuthDerived_t authkdf_real authkdf_ideal authkdf_not_pick q.

    Theorem authkdf_single_instance q LA A `{VA : ValidPackage LA I_authkdf A_export A} :
      fseparate LA [fmap count_loc] →
      fseparate LA [fmap slide_loc] →
      fseparate LA [fmap cell nat] →
      AdvantageE (COUNT AUTHKDF Key AuthDerived_t q ∘ AuthKdfReal)%pack
        (COUNT AUTHKDF Key AuthDerived_t q ∘ AuthKdfIdeal)%pack A
      = AdvantageE (COUNT AUTHKDF Key AuthDerived_t 1 ∘ AuthKdfReal)%pack
          (COUNT AUTHKDF Key AuthDerived_t 1 ∘ AuthKdfIdeal)%pack (A ∘ HybAuthKdf q)%pack *+ q.
    Proof.
      move=> S1 S2 S3.
      have -> : pack AuthKdfReal = pack (INST AUTHKDF Key AuthDerived_t authkdf_real authkdf_ideal true)
        by [].
      have -> : pack AuthKdfIdeal = pack (INST AUTHKDF Key AuthDerived_t authkdf_real authkdf_ideal false)
        by [].
      exact: multi_to_single_instance.
    Qed.

    Definition WirePlain_t :=
      chProd Cookie_t (chProd Salt (chProd Tag_t (chProd Residues_t Reply_t))).
    Definition PassiveView_t :=
      chProd McPK_t (chProd McCt_t (chProd ClientPK
        (chProd Cookie_t (chProd Wire_t SessionKey)))).

    Context (seal_wire : ChanKeys_t -> WirePlain_t -> 'I_(2 ^ wire_coin_bits) -> Wire_t).

    Definition honest_reply (pk : ClientPK) (msg : Message_t) (salt : Salt) : Reply_t :=
      let theta := (fo_derive pk msg salt).2 in
      lethe_reply (h_of_seed pk.1) (residues_of pk.2) msg
        (coins_of_seed theta) (mu_of_seed theta) (tau_of_seed theta).

    Definition passive_view (mpk : McPK_t) (c : McCt_t) (pk : ClientPK) (cookie : Cookie_t)
      (ch : ChanKeys_t) (salt : Salt) (gamma : Tag_t) (reply : Reply_t) (wc : 'I_(2 ^ wire_coin_bits))
      (ks_out : SessionKey) : PassiveView_t :=
      (mpk, (c, (pk, (cookie,
        (seal_wire ch (cookie, (salt, (gamma, (residues_of pk.2, reply)))) wc, ks_out))))).

    Definition SESSION_P : ident := 11%N.

    Definition I_passive : Interface :=
      [interface #val #[ SESSION_P ] : 'unit → 'ch(PassiveView_t) ].

    #[local] Notation G1Session :=
      (Session seed_bits coins_of_seed mu_of_seed tau_of_seed hseed_bits keygen_bits
         salt_bits key_bits auth_bits session_bits transcript_bits McCt_t Tag_t
         h_of_seed keygen fo_derive kdf confirm).
    #[local] Notation G1I := (I_session hseed_bits salt_bits auth_bits session_bits McCt_t Tag_t).
    #[local] Notation G1View := (View_t hseed_bits salt_bits session_bits Tag_t).
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
      (R_masks hseed_bits salt_bits key_bits auth_bits session_bits transcript_bits McCt_t Tag_t
         kdf confirm).
    #[local] Notation G1R_kem :=
      (R_kem hseed_bits salt_bits key_bits auth_bits session_bits transcript_bits McCt_t Tag_t
         kdf confirm).
    #[local] Notation G1R_kdf :=
      (R_kdf seed_bits coins_of_seed hseed_bits keygen_bits salt_bits key_bits auth_bits
         session_bits transcript_bits McCt_t Tag_t h_of_seed keygen fo_derive confirm).

    Definition Passive (replace : bool) : package emptym I_passive :=
      [package [fmap mlkem_loc ; cookie_loc] ;
        #def #[ SESSION_P ] (_ : 'unit) : 'ch(PassiveView_t) {
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          let pk := keygen kc in
          mk ← get mlkem_loc ;;
          mpk ← (match mk with
                 | Some p => ret p
                 | None => kr ← sample uniform (2 ^ mlkem_key_bits) ;;
                           #put mlkem_loc := Some (mlkem_keygen kr) ;;
                           ret (mlkem_keygen kr)
                 end) ;;
          r ← sample uniform (2 ^ mlkem_coin_bits) ;;
          fresh ← sample uniform (2 ^ session_bits) ;;
          kk ← get cookie_loc ;;
          ck ← (match kk with
                | Some k => ret k
                | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                          #put cookie_loc := Some k ;;
                          ret k
                end) ;;
          n ← sample uniform (2 ^ cookie_nonce_bits) ;;
          wc ← sample uniform (2 ^ wire_coin_bits) ;;
          let '(c, k_auth) := mlkem_encaps mpk r in
          let '(K, theta) := fo_derive pk msg salt in
          let keys := kdf K k_auth in
          let cookie := seal_cookie ck (cookie_plain theta msg pk k_auth) n in
          ret (passive_view mpk c pk cookie (chan_keys k_auth) salt (confirm keys.2 pk salt c)
                 (honest_reply pk msg salt) wc
                 (exported_key session_bits transcript_bits replace keys fresh))
        }
      ].

    Definition R_passive_m : package I_session_m I_passive :=
      [package emptym ;
        #def #[ SESSION_P ] (_ : 'unit) : 'ch(PassiveView_t) {
          #import {sig #[ SESSION_M ] : 'ch(HqcSide_t) → 'ch(ViewM_t)} as session ;;
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          let pk := keygen kc in
          v ← session (pk, (msg, salt)) ;;
          wc ← sample uniform (2 ^ wire_coin_bits) ;;
          let '(mpk, (c, (cookie, (ch, (gamma, ks_out))))) := v in
          ret (passive_view mpk c pk cookie ch salt gamma (honest_reply pk msg salt) wc ks_out)
        }
      ].

    Definition R_passive_cookie (replace : bool) : package I_cookie I_passive :=
      [package [fmap mlkem_loc] ;
        #def #[ SESSION_P ] (_ : 'unit) : 'ch(PassiveView_t) {
          #import {sig #[ COOKIE ] : 'ch(CookiePlain_t) → 'ch(Cookie_t)} as seal ;;
          kc ← sample uniform (2 ^ keygen_bits) ;;
          msg ← sample uniform (2 ^ k) ;;
          salt ← sample uniform (2 ^ salt_bits) ;;
          let pk := keygen kc in
          mk ← get mlkem_loc ;;
          mpk ← (match mk with
                 | Some p => ret p
                 | None => kr ← sample uniform (2 ^ mlkem_key_bits) ;;
                           #put mlkem_loc := Some (mlkem_keygen kr) ;;
                           ret (mlkem_keygen kr)
                 end) ;;
          r ← sample uniform (2 ^ mlkem_coin_bits) ;;
          fresh ← sample uniform (2 ^ session_bits) ;;
          let '(c, k_auth) := mlkem_encaps mpk r in
          let '(K, theta) := fo_derive pk msg salt in
          cookie ← seal (cookie_plain theta msg pk k_auth) ;;
          wc ← sample uniform (2 ^ wire_coin_bits) ;;
          let keys := kdf K k_auth in
          ret (passive_view mpk c pk cookie (chan_keys k_auth) salt (confirm keys.2 pk salt c)
                 (honest_reply pk msg salt) wc
                 (exported_key session_bits transcript_bits replace keys fresh))
        }
      ].

    Definition R_passive_g1 : package G1I I_passive :=
      [package [fmap mlkem_loc] ;
        #def #[ SESSION_P ] (_ : 'unit) : 'ch(PassiveView_t) {
          #import {sig #[ SESSION ] : 'ch(SessionArg_t auth_bits McCt_t) → 'ch(G1View)} as session ;;
          mk ← get mlkem_loc ;;
          mpk ← (match mk with
                 | Some p => ret p
                 | None => kr ← sample uniform (2 ^ mlkem_key_bits) ;;
                           #put mlkem_loc := Some (mlkem_keygen kr) ;;
                           ret (mlkem_keygen kr)
                 end) ;;
          r ← sample uniform (2 ^ mlkem_coin_bits) ;;
          let '(c, k_auth) := mlkem_encaps mpk r in
          v ← session (k_auth, c) ;;
          cookie ← sample uniform (2 ^ cookie_bits) ;;
          wc ← sample uniform (2 ^ wire_coin_bits) ;;
          let '(pk, (_, (salt, (reply, (gamma, ks_out))))) := v in
          ret (passive_view mpk c pk cookie (chan_keys k_auth) salt gamma reply wc ks_out)
        }
      ].

    Lemma passive_is_m_reduction b :
      Passive b ≈₀ (R_passive_m ∘ SessionM b)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel u.
      simplify_linking.
      ssprove_code_simpl.
      sync_all.
      all: close_same.
    Qed.

    Lemma passive_is_cookie_reduction b :
      Passive b ≈₀ (R_passive_cookie b ∘ CookieReal)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel u.
      simplify_linking.
      sync_all.
      all: close_same.
    Qed.

    Lemma ideal_cookie_is_g1_reduction b :
      (R_passive_cookie b ∘ CookieIdeal)%pack ≈₀ (R_passive_g1 ∘ G1Session b)%pack.
    Proof.
      eapply eq_rel_perf_ind_eq.
      simplify_eq_rel u.
      simplify_linking.
      ssprove_code_simpl.
      rewrite /honest_reply.
      ssprove_swap_seq_lhs [:: 2%N ; 1%N ; 0%N ].
      ssprove_sync_eq => mk.
      case: mk => [p|] /=; ssprove_code_simpl.
      - ssprove_swap_seq_lhs [:: 2%N ; 1%N ; 0%N ; 3%N ; 2%N ; 1%N ].
        sync_all.
        close_same.
      - ssprove_swap_seq_lhs [:: 2%N ; 1%N ; 0%N ; 3%N ; 2%N ; 1%N ; 4%N ; 3%N ; 2%N ].
        ssprove_sync_eq => ?.
        ssprove_sync_eq.
        ssprove_sync_eq => r.
        case: (mlkem_encaps _ r) => [c k_auth] /=.
        ssprove_code_simpl.
        ssprove_swap_seq_lhs [:: 2%N ; 1%N ; 0%N ].
        sync_all.
        close_same.
    Qed.

    Theorem passive_secrecy_if_mlkem_holds :
      ∀ LA A,
        ValidPackage LA I_passive A_export A →
        fseparate LA [fmap mlkem_loc] →
        fseparate LA [fmap cookie_loc] →
        AdvantageE (Passive false) (Passive true) A
        <= (AdvantageE MlkemReal MlkemIdeal ((A ∘ R_passive_m) ∘ R_mlkem false)%pack
            + AdvantageE CookieReal CookieIdeal ((A ∘ R_passive_m) ∘ R_cookie false)%pack
            + AdvantageE AuthKdfReal AuthKdfIdeal ((A ∘ R_passive_m) ∘ R_authkdf false)%pack)
           + (AdvantageE MlkemReal MlkemIdeal ((A ∘ R_passive_m) ∘ R_mlkem true)%pack
              + AdvantageE CookieReal CookieIdeal ((A ∘ R_passive_m) ∘ R_cookie true)%pack
              + AdvantageE AuthKdfReal AuthKdfIdeal ((A ∘ R_passive_m) ∘ R_authkdf true)%pack).
    Proof.
      move=> LA A VA SM SC.
      ssprove triangle (Passive false) [::
        (R_passive_m ∘ SessionM false)%pack ;
        (R_passive_m ∘ SessionM true)%pack
      ] (Passive true) A as ineq.
      eapply Order.POrderTheory.le_trans; first exact: ineq.
      erewrite (passive_is_m_reduction false LA A VA); try fmap_solve.
      all: try solve_sep.
      rewrite [X in _ + X <= _]Advantage_sym.
      erewrite (passive_is_m_reduction true LA A VA).
      all: try solve_sep.
      rewrite GRing.add0r GRing.addr0 -Advantage_link.
      have VAR : ValidPackage (unionm LA emptym) I_session_m A_export (A ∘ R_passive_m)%pack.
      { exact _. }
      refine (session_key_secrecy_mlkem _ _ VAR _ _); solve_sep.
    Qed.

    Theorem passive_secrecy_if_hqc_holds :
      ∀ LA A,
        ValidPackage LA I_passive A_export A →
        fseparate LA [fmap mlkem_loc] →
        fseparate LA [fmap cookie_loc] →
        AdvantageE (Passive false) (Passive true) A
        <= (AdvantageE CookieReal CookieIdeal (A ∘ R_passive_cookie false)%pack
            + AdvantageE CookieReal CookieIdeal (A ∘ R_passive_cookie true)%pack)
           + ((AdvantageE G1MasksReal G1MasksIdeal ((A ∘ R_passive_g1) ∘ G1R_masks false)%pack
               + AdvantageE G1KEMReal G1KEMIdeal ((A ∘ R_passive_g1) ∘ G1R_kem false)%pack
               + AdvantageE G1KDFReal G1KDFIdeal ((A ∘ R_passive_g1) ∘ G1R_kdf false)%pack)
              + (AdvantageE G1MasksReal G1MasksIdeal ((A ∘ R_passive_g1) ∘ G1R_masks true)%pack
                 + AdvantageE G1KEMReal G1KEMIdeal ((A ∘ R_passive_g1) ∘ G1R_kem true)%pack
                 + AdvantageE G1KDFReal G1KDFIdeal ((A ∘ R_passive_g1) ∘ G1R_kdf true)%pack)).
    Proof.
      move=> LA A VA SM SC.
      ssprove triangle (Passive false) [::
        (R_passive_cookie false ∘ CookieReal)%pack ;
        (R_passive_cookie false ∘ CookieIdeal)%pack ;
        (R_passive_g1 ∘ G1Session false)%pack ;
        (R_passive_g1 ∘ (G1R_kdf false ∘ G1KDFIdeal))%pack ;
        (R_passive_g1 ∘ (G1R_kdf true ∘ G1KDFIdeal))%pack ;
        (R_passive_g1 ∘ G1Session true)%pack ;
        (R_passive_cookie true ∘ CookieIdeal)%pack ;
        (R_passive_cookie true ∘ CookieReal)%pack
      ] (Passive true) A as ineq.
      eapply Order.POrderTheory.le_trans; first exact: ineq.
      have VG : ValidPackage (unionm LA [fmap mlkem_loc]) G1I A_export (A ∘ R_passive_g1)%pack.
      { exact _. }
      have Z1 : AdvantageE (Passive false) (R_passive_cookie false ∘ CookieReal)%pack A = 0.
      { apply: passive_is_cookie_reduction; solve_sep. }
      have Z2 : AdvantageE (R_passive_cookie false ∘ CookieIdeal)%pack
                  (R_passive_g1 ∘ G1Session false)%pack A = 0.
      { apply: ideal_cookie_is_g1_reduction; solve_sep. }
      have Z3 : AdvantageE (R_passive_g1 ∘ (G1R_kdf false ∘ G1KDFIdeal))%pack
                  (R_passive_g1 ∘ (G1R_kdf true ∘ G1KDFIdeal))%pack A = 0.
      { rewrite -Advantage_link.
        refine (replaced_key_is_uniform seed_bits coins_of_seed hseed_bits keygen_bits salt_bits
                  key_bits auth_bits session_bits transcript_bits McCt_t Tag_t h_of_seed keygen
                  fo_derive confirm _ _ VG _ _); solve_sep. }
      have Z4 : AdvantageE (R_passive_g1 ∘ G1Session true)%pack
                  (R_passive_cookie true ∘ CookieIdeal)%pack A = 0.
      { rewrite Advantage_sym. apply: ideal_cookie_is_g1_reduction; solve_sep. }
      have Z5 : AdvantageE (R_passive_cookie true ∘ CookieReal)%pack (Passive true) A = 0.
      { rewrite Advantage_sym. apply: passive_is_cookie_reduction; solve_sep. }
      have H1 := session_hops seed_bits coins_of_seed mu_of_seed tau_of_seed hseed_bits
                   keygen_bits salt_bits key_bits auth_bits session_bits transcript_bits McCt_t
                   Tag_t h_of_seed keygen fo_derive kdf confirm false _ _ VG.
      have H2 := session_hops seed_bits coins_of_seed mu_of_seed tau_of_seed hseed_bits
                   keygen_bits salt_bits key_bits auth_bits session_bits transcript_bits McCt_t
                   Tag_t h_of_seed keygen fo_derive kdf confirm true _ _ VG.
      rewrite (Advantage_link (G1Session false) (G1R_kdf false ∘ G1KDFIdeal)%pack A R_passive_g1) in H1.
      rewrite (Advantage_link (G1Session true) (G1R_kdf true ∘ G1KDFIdeal)%pack A R_passive_g1)
        Advantage_sym in H2.
      rewrite Z1 Z2 Z3 Z4 Z5 !GRing.addr0 GRing.add0r.
      rewrite -(Advantage_link CookieReal CookieIdeal A (R_passive_cookie false)).
      rewrite (Advantage_sym (R_passive_cookie true ∘ CookieIdeal)%pack).
      rewrite -(Advantage_link CookieReal CookieIdeal A (R_passive_cookie true)).
      rewrite [X in X <= _]sum4_regroup.
      apply: Num.Theory.lerD; first done.
      exact: Num.Theory.lerD H1 H2.
    Qed.

    Theorem passive_secrecy_unless_both_fall :
      ∀ LA A,
        ValidPackage LA I_passive A_export A →
        fseparate LA [fmap mlkem_loc] →
        fseparate LA [fmap cookie_loc] →
        AdvantageE (Passive false) (Passive true) A
        <= (AdvantageE MlkemReal MlkemIdeal ((A ∘ R_passive_m) ∘ R_mlkem false)%pack
            + AdvantageE CookieReal CookieIdeal ((A ∘ R_passive_m) ∘ R_cookie false)%pack
            + AdvantageE AuthKdfReal AuthKdfIdeal ((A ∘ R_passive_m) ∘ R_authkdf false)%pack)
           + (AdvantageE MlkemReal MlkemIdeal ((A ∘ R_passive_m) ∘ R_mlkem true)%pack
              + AdvantageE CookieReal CookieIdeal ((A ∘ R_passive_m) ∘ R_cookie true)%pack
              + AdvantageE AuthKdfReal AuthKdfIdeal ((A ∘ R_passive_m) ∘ R_authkdf true)%pack)
        ∧
        AdvantageE (Passive false) (Passive true) A
        <= (AdvantageE CookieReal CookieIdeal (A ∘ R_passive_cookie false)%pack
            + AdvantageE CookieReal CookieIdeal (A ∘ R_passive_cookie true)%pack)
           + ((AdvantageE G1MasksReal G1MasksIdeal ((A ∘ R_passive_g1) ∘ G1R_masks false)%pack
               + AdvantageE G1KEMReal G1KEMIdeal ((A ∘ R_passive_g1) ∘ G1R_kem false)%pack
               + AdvantageE G1KDFReal G1KDFIdeal ((A ∘ R_passive_g1) ∘ G1R_kdf false)%pack)
              + (AdvantageE G1MasksReal G1MasksIdeal ((A ∘ R_passive_g1) ∘ G1R_masks true)%pack
                 + AdvantageE G1KEMReal G1KEMIdeal ((A ∘ R_passive_g1) ∘ G1R_kem true)%pack
                 + AdvantageE G1KDFReal G1KDFIdeal ((A ∘ R_passive_g1) ∘ G1R_kdf true)%pack)).
    Proof.
      move=> LA A VA SM SC.
      split.
      - exact: passive_secrecy_if_mlkem_holds.
      - exact: passive_secrecy_if_hqc_holds.
    Qed.

  End MLKEMSide.
End HQCLetheBoth.

Module HQCLetheBothFor (H : HQCParams) (M : CRTModuli H).
  Module Params <: HQCLetheParams.
    Include H.
    Include M.
  End Params.
  Include HQCLetheBoth Params.
End HQCLetheBothFor.

Module HQCLetheBoth1 (E : HQC1Encoding) (M : CRTModuli HQC1Consts).
  Module Base := HQC1 E.
  Include HQCLetheBothFor Base M.
End HQCLetheBoth1.
Module HQCLetheBoth3 (E : HQC3Encoding) (M : CRTModuli HQC3Consts).
  Module Base := HQC3 E.
  Include HQCLetheBothFor Base M.
End HQCLetheBoth3.
Module HQCLetheBoth5 (E : HQC5Encoding) (M : CRTModuli HQC5Consts).
  Module Base := HQC5 E.
  Include HQCLetheBothFor Base M.
End HQCLetheBoth5.
