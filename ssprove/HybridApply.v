Set Warnings "-notation-overridden,-ambiguous-paths".
From mathcomp Require Import all_ssreflect all_algebra reals distr realsum ssralg.
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

From SSProveHQC Require Import MLKEMCCA ActiveSecrecy RequestIntegrity HybridInst.

Notation " 'ch ( x ) " := x (in custom pack_type at level 2, x constr).
Notation " 'ch ( x ) " := x (at level 2) : package_scope.


Section PrfHybrid.

  Context (auth_bits session_bits transcript_bits chan_bits : nat).
  Context (Key_t : choice_type).

  #[local] Notation AuthKey := (MlkemKey_t auth_bits).
  #[local] Notation SessionKey := (SessionKey_t session_bits).
  #[local] Notation TransKey := (TransKey_t transcript_bits).
  #[local] Notation ChanKeys := (ChanKeys_t chan_bits).
  #[local] Notation EvalIn := (EvalIn_t Key_t).
  #[local] Notation TestIn := (TestIn_t Key_t).

  Context (kdf : Key_t → AuthKey → SessionKey * TransKey).
  Context (chan_keys : AuthKey → ChanKeys).

  #[local] Notation no_key := (ActiveSecrecy.no_key auth_bits).
  #[local] Notation untestable := (ActiveSecrecy.untestable auth_bits).
  #[local] Notation kmap_loc := (ActiveSecrecy.kmap_loc auth_bits).
  #[local] Notation ttab_loc := (ActiveSecrecy.ttab_loc transcript_bits Key_t).
  #[local] Notation ctab_loc := (ActiveSecrecy.ctab_loc chan_bits).
  #[local] Notation I_prf_a := (I_prf session_bits transcript_bits chan_bits Key_t).
  #[local] Notation PrfReal_a := (PrfReal auth_bits session_bits transcript_bits chan_bits Key_t kdf chan_keys).
  #[local] Notation PrfIdeal_a := (PrfIdeal auth_bits session_bits transcript_bits chan_bits Key_t kdf chan_keys).

  Definition PrfSt_t := chProd AuthKey (chProd (chMap Key_t TransKey) (chProd (chOption ChanKeys) 'bool)).
  Definition PrfArg_t := chSum Key_t (chSum 'unit Key_t).
  Definition PrfRes_t := chSum TransKey (chSum ChanKeys (chOption SessionKey)).

  Definition prf_new (_ : bool) : dist PrfSt_t :=
    {code k ← sample uniform (2 ^ auth_bits) ;; ret (k, (emptym, (None, false)))}.

  Definition prf_absent (a : PrfArg_t) : PrfRes_t :=
    match a with
    | inl K => inl (kdf K no_key).2
    | inr (inl _) => inr (inl (chan_keys no_key))
    | inr (inr _) => inr (inr None)
    end.

  Definition prf_query (b : bool) (s : PrfSt_t) (a : PrfArg_t) : dist (chProd PrfSt_t PrfRes_t) :=
    {code
      match a with
      | inl K =>
          if b then ret (s, inl (kdf K s.1).2) else
          match s.2.1 K with
          | Some kt => ret (s, inl kt)
          | None =>
              kt ← sample uniform (2 ^ transcript_bits) ;;
              ret ((s.1, (setm s.2.1 K kt, s.2.2)), inl kt)
          end
      | inr (inl _) =>
          if b then ret (s, inr (inl (chan_keys s.1))) else
          match s.2.2.1 with
          | Some ch => ret (s, inr (inl ch))
          | None =>
              ch ← sample uniform (2 ^ chan_bits) ;;
              ret ((s.1, (s.2.1, (Some ch, s.2.2.2))), inr (inl ch))
          end
      | inr (inr K) =>
          if s.2.2.2 then ret (s, inr (inr None)) else
          if b then ret ((s.1, (s.2.1, (s.2.2.1, true))), inr (inr (Some (kdf K s.1).1))) else
          ks ← sample uniform (2 ^ session_bits) ;;
          ret ((s.1, (s.2.1, (s.2.2.1, true))), inr (inr (Some ks)))
      end
    }.

  #[local] Notation I_multi_p := (I_multi PrfArg_t PrfRes_t).
  #[local] Notation MULTI_p q := (MULTI PrfSt_t PrfArg_t PrfRes_t q prf_new prf_query prf_absent).
  #[local] Notation SINGLE_p := (SINGLE PrfSt_t PrfArg_t PrfRes_t prf_new prf_query prf_absent).
  #[local] Notation HYB_p q := (HYB PrfSt_t PrfArg_t PrfRes_t q prf_new prf_query prf_absent).

  Definition W_prf : package I_multi_p I_prf_a :=
    [package emptym ;
      #def #[ NEW_INST ] (_ : 'unit) : 'nat {
        #import {sig #[ NEWI ] : 'unit → 'nat} as newi ;;
        i ← newi Datatypes.tt ;;
        ret i
      } ;
      #def #[ EVAL_T ] (x : 'ch(EvalIn)) : 'ch(TransKey) {
        #import {sig #[ QUERYI ] : 'ch(chProd 'nat PrfArg_t) → 'ch(PrfRes_t)} as queryi ;;
        r ← queryi (x.1, inl x.2) ;;
        ret (match r with inl kt => kt | _ => (kdf x.2 no_key).2 end)
      } ;
      #def #[ CHAN ] (i : 'nat) : 'ch(ChanKeys) {
        #import {sig #[ QUERYI ] : 'ch(chProd 'nat PrfArg_t) → 'ch(PrfRes_t)} as queryi ;;
        r ← queryi (i, inr (inl Datatypes.tt)) ;;
        ret (match r with inr (inl ch) => ch | _ => chan_keys no_key end)
      } ;
      #def #[ SESSION_KEY ] (ti : 'ch(TestIn)) : 'ch(chOption SessionKey) {
        #import {sig #[ QUERYI ] : 'ch(chProd 'nat PrfArg_t) → 'ch(PrfRes_t)} as queryi ;;
        r ← queryi (ti.1, inr (inr ti.2)) ;;
        ret (match r with inr (inr o) => o | _ => None end)
      }
    ].

  Definition pbound_loc : Location := mkloc 140 (0%N : 'nat).

  Definition BoundPrf (q : nat) : package I_prf_a I_prf_a :=
    [package [fmap pbound_loc] ;
      #def #[ NEW_INST ] (_ : 'unit) : 'nat {
        #import {sig #[ NEW_INST ] : 'unit → 'nat} as new_inst ;;
        c ← get pbound_loc ;;
        if (c < q)%N then
          i ← new_inst Datatypes.tt ;;
          #put pbound_loc := c.+1 ;;
          ret i
        else ret c
      } ;
      #def #[ EVAL_T ] (x : 'ch(EvalIn)) : 'ch(TransKey) {
        #import {sig #[ EVAL_T ] : 'ch(EvalIn) → 'ch(TransKey)} as eval_t ;;
        r ← eval_t x ;;
        ret r
      } ;
      #def #[ CHAN ] (i : 'nat) : 'ch(ChanKeys) {
        #import {sig #[ CHAN ] : 'nat → 'ch(ChanKeys)} as chan ;;
        r ← chan i ;;
        ret r
      } ;
      #def #[ SESSION_KEY ] (ti : 'ch(TestIn)) : 'ch(chOption SessionKey) {
        #import {sig #[ SESSION_KEY ] : 'ch(TestIn) → 'ch(chOption SessionKey)} as session_key ;;
        r ← session_key ti ;;
        ret r
      }
    ].


  #[local] Notation tested_loc := ActiveSecrecy.tested_loc.
  #[local] Notation icount_p := (icount_loc).
  #[local] Notation imap_p := (imap_loc PrfSt_t).

  Definition prf_keys (K : seq AuthKey) (M : chMap 'nat PrfSt_t) : Prop :=
    ∀ i, match M i with
         | Some st => (i < size K)%N ∧ st.1 = nth no_key K i
         | None => (size K <= i)%N
         end.

  Definition prf_tested (T : chMap 'nat 'unit) (M : chMap 'nat PrfSt_t) : Prop :=
    ∀ i, match M i with
         | Some st => st.2.2.2 = (i \in domm T)
         | None => i \notin domm T
         end.

  Definition prf_tt (TT : chMap EvalIn TransKey) (M : chMap 'nat PrfSt_t) : Prop :=
    ∀ i K', match M i with
            | Some st => st.2.1 K' = TT (i, K')
            | None => TT (i, K') = None
            end.

  Definition prf_ct (CT : chMap 'nat ChanKeys) (M : chMap 'nat PrfSt_t) : Prop :=
    ∀ i, match M i with
         | Some st => st.2.2.1 = CT i
         | None => CT i = None
         end.

  Lemma prf_keys_some K M i st : prf_keys K M → M i = Some st → (i < size K)%N ∧ st.1 = nth no_key K i.
  Proof. move=> H E; move: (H i); by rewrite E. Qed.

  Lemma prf_keys_none K M i : prf_keys K M → M i = None → (size K <= i)%N.
  Proof. move=> H E; move: (H i); by rewrite E. Qed.

  Lemma prf_keys_fresh K M : prf_keys K M → M (size K) = None.
  Proof. move=> H; case E: (M (size K)) => [st|] //; move: (H (size K)); by rewrite E ltnn => -[]. Qed.

  Lemma prf_keys_new K M k x : prf_keys K M → prf_keys (rcons K k) (setm M (size K) (k, x)).
  Proof.
    move=> H i; rewrite setmE size_rcons.
    case E: (i == size K)%B.
    - move/eqP: E => ->; by rewrite ltnSn nth_rcons ltnn eqxx.
    - move: (H i); case: (M i) => [st|].
      + move=> [Hi Hk]; by rewrite nth_rcons Hi ltnW.
      + move=> Hi; by rewrite ltn_neqAle eq_sym E Hi.
  Qed.

  Lemma prf_keys_upd K M i st st' : prf_keys K M → M i = Some st → st'.1 = st.1 →
    prf_keys K (setm M i st').
  Proof.
    move=> H E E1 j; rewrite setmE; case F: (j == i)%B; last exact: H.
    move/eqP: F => ->; rewrite E1; move: (H i); by rewrite E.
  Qed.

  Lemma prf_tested_new T K M k x : prf_keys K M → prf_tested T M →
    prf_tested T (setm M (size K) (k, (x, (None, false)))).
  Proof.
    move=> Hk Ht i; rewrite setmE; case E: (i == size K)%B; last exact: Ht.
    move/eqP: E => ->; move: (Ht (size K)); rewrite (prf_keys_fresh _ _ Hk) /=.
    by move/negbTE.
  Qed.

  Lemma prf_tested_upd T M i st st' : prf_tested T M → M i = Some st → st'.2.2.2 = st.2.2.2 →
    prf_tested T (setm M i st').
  Proof.
    move=> H E E1 j; rewrite setmE; case F: (j == i)%B; last exact: H.
    move/eqP: F => ->; rewrite E1; move: (H i); by rewrite E.
  Qed.

  Lemma prf_tested_test T M i st st' : prf_tested T M → M i = Some st → st'.2.2.2 = true →
    prf_tested (setm T i Datatypes.tt) (setm M i st').
  Proof.
    move=> H E E1 j; rewrite setmE domm_set in_fsetU in_fset1.
    case F: (j == i)%B => /=; first by rewrite E1.
    exact: H.
  Qed.

  Lemma prf_tt_new TT K M k x : prf_keys K M → prf_tt TT M →
    prf_tt TT (setm M (size K) (k, (emptym, x))).
  Proof.
    move=> Hk Ht i K'; rewrite setmE; case E: (i == size K)%B; last exact: Ht.
    move/eqP: E => ->; move: (Ht (size K) K'); rewrite (prf_keys_fresh _ _ Hk) /= emptymE.
    by move=> ->.
  Qed.

  Lemma prf_tt_upd TT M i st st' : prf_tt TT M → M i = Some st → st'.2.1 = st.2.1 →
    prf_tt TT (setm M i st').
  Proof.
    move=> H E E1 j K'; rewrite setmE; case F: (j == i)%B; last exact: H.
    move/eqP: F => ->; rewrite E1; move: (H i K'); by rewrite E.
  Qed.

  Lemma prf_tt_sample TT M i K' st kt : prf_tt TT M → M i = Some st →
    prf_tt (setm TT (i, K') kt) (setm M i (st.1, (setm st.2.1 K' kt, st.2.2))).
  Proof.
    move=> H E j K''; rewrite !setmE; case F: (j == i)%B => /=.
    - move/eqP: F => ->; move: (H i K''); rewrite E => <-.
      rewrite setmE; case E2: (K'' == K')%B; case E3: ((i, K'') == (i, K'))%B => //.
      + move/eqP: E2 => E2; subst; by rewrite eqxx in E3.
      + move/eqP: E3 => [] E4; subst; by rewrite eqxx in E2.
    - move: (H j K''); case: (M j) => [st'|] ->;
      by rewrite xpair_eqE F.
  Qed.

  Lemma prf_ct_new CT K M k x y : prf_keys K M → prf_ct CT M →
    prf_ct CT (setm M (size K) (k, (x, (None, y)))).
  Proof.
    move=> Hk Ht i; rewrite setmE; case E: (i == size K)%B; last exact: Ht.
    move/eqP: E => ->; move: (Ht (size K)); rewrite (prf_keys_fresh _ _ Hk) /=.
    by move=> ->.
  Qed.

  Lemma prf_ct_upd CT M i st st' : prf_ct CT M → M i = Some st → st'.2.2.1 = st.2.2.1 →
    prf_ct CT (setm M i st').
  Proof.
    move=> H E E1 j; rewrite setmE; case F: (j == i)%B; last exact: H.
    move/eqP: F => ->; rewrite E1; move: (H i); by rewrite E.
  Qed.

  Lemma prf_ct_sample CT M i st ch : prf_ct CT M → M i = Some st →
    prf_ct (setm CT i ch) (setm M i (st.1, (st.2.1, (Some ch, st.2.2.2)))).
  Proof.
    move=> H E j; rewrite !setmE; case F: (j == i)%B => //.
    exact: H.
  Qed.

  Notation inv_prf_real :=
    (heap_ignore [fmap pbound_loc ; kmap_loc ; tested_loc ; icount_p ; imap_p] ⋊
     couple_cross pbound_loc icount_p eq ⋊
     couple_lhs pbound_loc kmap_loc (λ (c : 'nat) (K : seq AuthKey), size K = c) ⋊
     couple_cross kmap_loc imap_p prf_keys ⋊
     couple_cross tested_loc imap_p prf_tested ⋊
     rel_app [:: (rhs, imap_p)] (prf_tt emptym) ⋊
     rel_app [:: (rhs, imap_p)] (prf_ct emptym)).

  Lemma bound_real_is_multi q :
    (BoundPrf q ∘ PrfReal_a)%pack ≈₀ (W_prf ∘ MULTI_p q true)%pack.
  Proof.
    eapply eq_rel_perf_ind with inv_prf_real.
    { ssprove_invariant.
      all: rewrite /rel_empty /heap_init /=.
      all: try done.
      by move=> i; rewrite emptymE domm0. }
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    all: cbv zeta.
    - apply: r_get_remember_lhs => c.
      apply: r_get_remember_rhs => c'.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 5%N => Ec. subst c'.
      case Hcq: (c < q)%N => /=; last first.
      { ssprove_forget_all. by apply: r_ret. }
      ssprove_swap_lhs 0%N.
      apply: r_get_remember_lhs => K.
      ssprove_rem_rel 4%N => Hsz.
      ssprove_rem_rel 3%N => Hk.
      subst c.
      ssprove_sync => k.
      apply: r_put_lhs. apply: r_put_lhs. apply: r_put_rhs. apply: r_put_rhs.
      ssprove_restore_mem.
      + ssprove_invariant.
        * by move=> _; rewrite size_rcons.
        * exact: prf_keys_new.
        * move=> H; exact: prf_tested_new Hk H.
        * move=> H; exact: prf_tt_new Hk H.
        * move=> H; exact: prf_ct_new Hk H.
      + by apply: r_ret.
    - apply: r_get_remember_lhs => K.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 3%N => Hk.
      case HM: (M x.1) => [st|] /=.
      + have [Hi Hst] := prf_keys_some _ _ _ _ Hk HM.
        apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          all: move=> H; first [ by apply: (prf_keys_upd _ _ _ _ _ H HM)
                               | by apply: (prf_tested_upd _ _ _ _ _ H HM)
                               | by apply: (prf_tt_upd _ _ _ _ _ H HM)
                               | by apply: (prf_ct_upd _ _ _ _ _ H HM) ].
        * apply: r_ret => s0 s1 Hinv; split => //; by rewrite Hst.
      + have Hi := prf_keys_none _ _ _ Hk HM.
        ssprove_forget_all.
        apply: r_ret => s0 s1 Hinv; split => //; by rewrite nth_default.
    - apply: r_get_remember_lhs => K.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 3%N => Hk.
      case HM: (M x) => [st|] /=.
      + have [Hi Hst] := prf_keys_some _ _ _ _ Hk HM.
        apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          all: move=> H; first [ by apply: (prf_keys_upd _ _ _ _ _ H HM)
                               | by apply: (prf_tested_upd _ _ _ _ _ H HM)
                               | by apply: (prf_tt_upd _ _ _ _ _ H HM)
                               | by apply: (prf_ct_upd _ _ _ _ _ H HM) ].
        * apply: r_ret => s0 s1 Hinv; split => //; by rewrite Hst.
      + have Hi := prf_keys_none _ _ _ Hk HM.
        ssprove_forget_all.
        apply: r_ret => s0 s1 Hinv; split => //; by rewrite nth_default.
    - apply: r_get_remember_lhs => T.
      apply: r_get_remember_lhs => K.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 3%N => Hk.
      ssprove_rem_rel 2%N => Ht.
      case HM: (M x.1) => [st|] /=.
      + have [Hi Hst] := prf_keys_some _ _ _ _ Hk HM.
        have Hst2 : st.2.2.2 = (x.1 \in domm T) by move: (Ht x.1); rewrite HM.
        rewrite /untestable leqNgt Hi orbF -Hst2.
        case Htst: st.2.2.2 => /=.
        * apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant.
             all: move=> H; first [ by apply: (prf_keys_upd _ _ _ _ _ H HM)
                                  | by apply: (prf_tested_upd _ _ _ _ _ H HM)
                                  | by apply: (prf_tt_upd _ _ _ _ _ H HM)
                                  | by apply: (prf_ct_upd _ _ _ _ _ H HM) ].
          -- by apply: r_ret.
        * apply: r_put_lhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant.
             all: move=> H; first [ by apply: (prf_keys_upd _ _ _ _ _ H HM)
                                  | by apply: (prf_tested_test _ _ _ _ _ H HM)
                                  | by apply: (prf_tt_upd _ _ _ _ _ H HM)
                                  | by apply: (prf_ct_upd _ _ _ _ _ H HM) ].
          -- apply: r_ret => s0 s1 Hinv; split => //; by rewrite Hst.
      + have Hi := prf_keys_none _ _ _ Hk HM.
        rewrite /untestable Hi orbT /=.
        ssprove_forget_all.
        by apply: r_ret.
  Qed.


  Notation inv_prf_ideal :=
    (heap_ignore [fmap pbound_loc ; kmap_loc ; tested_loc ; ttab_loc ; ctab_loc ;
                  icount_p ; imap_p] ⋊
     couple_cross pbound_loc icount_p eq ⋊
     couple_lhs pbound_loc kmap_loc (λ (c : 'nat) (K : seq AuthKey), size K = c) ⋊
     couple_cross kmap_loc imap_p prf_keys ⋊
     couple_cross tested_loc imap_p prf_tested ⋊
     couple_cross ttab_loc imap_p prf_tt ⋊
     couple_cross ctab_loc imap_p prf_ct).

  Ltac upd_close HM :=
    let H := fresh "H" in
    move=> H; first [ by apply: (prf_keys_upd _ _ _ _ _ H HM)
                    | by apply: (prf_tested_upd _ _ _ _ _ H HM)
                    | by apply: (prf_tested_test _ _ _ _ _ H HM)
                    | by apply: (prf_tt_upd _ _ _ _ _ H HM)
                    | by apply: (prf_tt_sample _ _ _ _ _ _ H HM)
                    | by apply: (prf_ct_upd _ _ _ _ _ H HM)
                    | by apply: (prf_ct_sample _ _ _ _ _ H HM) ].

  Lemma bound_ideal_is_multi q :
    (BoundPrf q ∘ PrfIdeal_a)%pack ≈₀ (W_prf ∘ MULTI_p q false)%pack.
  Proof.
    eapply eq_rel_perf_ind with inv_prf_ideal.
    { ssprove_invariant.
      all: rewrite /rel_empty /heap_init /=.
      all: try done.
      by move=> i; rewrite emptymE domm0. }
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    all: cbv zeta.
    - apply: r_get_remember_lhs => c.
      apply: r_get_remember_rhs => c'.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 5%N => Ec. subst c'.
      case Hcq: (c < q)%N => /=; last first.
      { ssprove_forget_all. by apply: r_ret. }
      ssprove_swap_lhs 0%N.
      apply: r_get_remember_lhs => K.
      ssprove_rem_rel 4%N => Hsz.
      ssprove_rem_rel 3%N => Hk.
      subst c.
      ssprove_sync => k.
      apply: r_put_lhs. apply: r_put_lhs. apply: r_put_rhs. apply: r_put_rhs.
      ssprove_restore_mem.
      + ssprove_invariant.
        * by move=> _; rewrite size_rcons.
        * exact: prf_keys_new.
        * move=> H; exact: prf_tested_new Hk H.
        * move=> H; exact: prf_tt_new Hk H.
        * move=> H; exact: prf_ct_new Hk H.
      + by apply: r_ret.
    - case: x => i K' /=.
      apply: r_get_remember_lhs => K.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 3%N => Hk.
      case HM: (M i) => [st|] /=.
      + have [Hi Hst] := prf_keys_some _ _ _ _ Hk HM.
        rewrite Hi /=.
        apply: r_get_remember_lhs => TT.
        ssprove_rem_rel 1%N => Htt.
        have Est : st.2.1 K' = TT (i, K') by move: (Htt i K'); rewrite HM.
        rewrite Est.
        case HT: (TT (i, K')) => [kt|] /=.
        * apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant. all: upd_close HM.
          -- by apply: r_ret.
        * ssprove_sync => kt.
          apply: r_put_lhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant. all: upd_close HM.
          -- by apply: r_ret.
      + have Hi := prf_keys_none _ _ _ Hk HM.
        rewrite ltnNge Hi /=.
        ssprove_forget_all.
        by apply: r_ret.
    - apply: r_get_remember_lhs => K.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 3%N => Hk.
      case HM: (M x) => [st|] /=.
      + have [Hi Hst] := prf_keys_some _ _ _ _ Hk HM.
        rewrite Hi /=.
        apply: r_get_remember_lhs => CT.
        ssprove_rem_rel 0%N => Hct.
        have Est : st.2.2.1 = CT x by move: (Hct x); rewrite HM.
        rewrite Est.
        case HC: (CT x) => [ch|] /=.
        * apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant. all: upd_close HM.
          -- by apply: r_ret.
        * ssprove_sync => ch.
          apply: r_put_lhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant. all: upd_close HM.
          -- by apply: r_ret.
      + have Hi := prf_keys_none _ _ _ Hk HM.
        rewrite ltnNge Hi /=.
        ssprove_forget_all.
        by apply: r_ret.
    - apply: r_get_remember_lhs => T.
      apply: r_get_remember_lhs => K.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 3%N => Hk.
      ssprove_rem_rel 2%N => Ht.
      case HM: (M x.1) => [st|] /=.
      + have [Hi Hst] := prf_keys_some _ _ _ _ Hk HM.
        have Hst2 : st.2.2.2 = (x.1 \in domm T) by move: (Ht x.1); rewrite HM.
        rewrite /untestable leqNgt Hi orbF -Hst2.
        case Htst: st.2.2.2 => /=.
        * apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant. all: upd_close HM.
          -- by apply: r_ret.
        * apply: r_put_lhs.
          ssprove_sync => ks.
          apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant. all: upd_close HM.
          -- by apply: r_ret.
      + have Hi := prf_keys_none _ _ _ Hk HM.
        rewrite /untestable Hi orbT /=.
        ssprove_forget_all.
        by apply: r_ret.
  Qed.


  Theorem prf_single_instance q LA A :
    ValidPackage LA I_prf_a A_export A →
    fseparate LA [fmap pbound_loc] →
    fseparate LA [fmap kmap_loc ; tested_loc] →
    fseparate LA [fmap kmap_loc ; tested_loc ; ttab_loc ; ctab_loc] →
    fseparate LA [fmap imap_p ; icount_p] →
    fseparate LA [fmap hmap_loc PrfSt_t ; hcount_loc] →
    fseparate LA [fmap single_loc PrfSt_t] →
    AdvantageE (BoundPrf q ∘ PrfReal_a)%pack (BoundPrf q ∘ PrfIdeal_a)%pack A
    <= \sum_(j < q) AdvantageE (SINGLE_p true) (SINGLE_p false) ((A ∘ W_prf) ∘ HYB_p q j)%pack.
  Proof.
    move=> VA S0 S1 S1' S2 S3 S4.
    ssprove triangle (BoundPrf q ∘ PrfReal_a)%pack [::
      (W_prf ∘ MULTI_p q true)%pack ;
      (W_prf ∘ MULTI_p q false)%pack
    ] (BoundPrf q ∘ PrfIdeal_a)%pack A as ineq.
    eapply Order.POrderTheory.le_trans; first exact: ineq.
    have Z1 : AdvantageE (BoundPrf q ∘ PrfReal_a)%pack (W_prf ∘ MULTI_p q true)%pack A = 0.
    { apply: bound_real_is_multi.
      - apply: fseparateUr; [ exact: S0 | exact: S1 ].
      - apply: fseparateUr; [ exact: fseparatem0 | exact: S2 ]. }
    have Z2 : AdvantageE (BoundPrf q ∘ PrfIdeal_a)%pack (W_prf ∘ MULTI_p q false)%pack A = 0.
    { apply: bound_ideal_is_multi.
      - apply: fseparateUr; [ exact: S0 | exact: S1' ].
      - apply: fseparateUr; [ exact: fseparatem0 | exact: S2 ]. }
    rewrite Z1 [AdvantageE (W_prf ∘ MULTI_p q false)%pack _ _]Advantage_sym Z2 add0r addr0.
    rewrite -Advantage_link.
    have VA' : ValidPackage (unionm LA emptym) I_multi_p A_export (A ∘ W_prf)%pack.
    { ssprove_valid. }
    have T2 : fseparate (unionm LA emptym) [fmap imap_p ; icount_p].
    { apply: fseparateUl; [ exact: S2 | exact: fseparate0m ]. }
    have T3 : fseparate (unionm LA emptym) [fmap hmap_loc PrfSt_t ; hcount_loc].
    { apply: fseparateUl; [ exact: S3 | exact: fseparate0m ]. }
    have T4 : fseparate (unionm LA emptym) [fmap single_loc PrfSt_t].
    { apply: fseparateUl; [ exact: S4 | exact: fseparate0m ]. }
    exact: (multi_instance_hybrid_sum PrfSt_t PrfArg_t PrfRes_t q prf_new prf_query prf_absent
              (unionm LA emptym) (A ∘ W_prf)%pack VA' T2 T3 T4).
  Qed.

End PrfHybrid.


Section ReqHybrid.

  Context (req_key_bits : nat).
  Context (ReqHdr_t ReqCookie_t ReqSealed_t ReqPayload_t : choice_type).

  #[local] Notation Key := (ReqKey_t req_key_bits).
  #[local] Notation SealIn := (SealIn_t ReqHdr_t ReqCookie_t ReqPayload_t).
  #[local] Notation Packet := (ReqPacket_t ReqHdr_t ReqCookie_t ReqSealed_t).

  Context (seal_req : Key → ReqHdr_t → ReqCookie_t → ReqPayload_t → ReqSealed_t).
  Context (open_req : Key → ReqHdr_t → ReqCookie_t → ReqSealed_t → option ReqPayload_t).

  #[local] Notation no_key := (no_req_key req_key_bits).
  #[local] Notation rkeys := (rkeys_loc req_key_bits).
  #[local] Notation rnonce := (rnonce_loc ReqHdr_t ReqCookie_t ReqPayload_t).
  #[local] Notation rsealed := (rsealed_loc ReqHdr_t ReqCookie_t ReqSealed_t ReqPayload_t).
  #[local] Notation I_req := (I_req_aead ReqHdr_t ReqCookie_t ReqSealed_t ReqPayload_t).
  #[local] Notation ReqReal := (ReqAeadReal req_key_bits ReqHdr_t ReqCookie_t ReqSealed_t ReqPayload_t seal_req open_req).
  #[local] Notation ReqIdeal := (ReqAeadIdeal req_key_bits ReqHdr_t ReqCookie_t ReqSealed_t ReqPayload_t seal_req).

  Definition HC_t := chProd ReqHdr_t ReqCookie_t.
  Definition Pkt_t := chProd ReqHdr_t (chProd ReqCookie_t ReqSealed_t).
  Definition ReqSt_t := chProd Key (chProd (chMap HC_t ReqPayload_t) (chMap Pkt_t ReqPayload_t)).
  Definition ReqArg_t := chSum (chProd ReqHdr_t (chProd ReqCookie_t ReqPayload_t)) Pkt_t.
  Definition ReqRes_t := chSum (chOption ReqSealed_t) (chOption ReqPayload_t).

  Definition fresh_nonce (N : chMap HC_t ReqPayload_t) (hc : HC_t) (p : ReqPayload_t) : bool :=
    match N hc with
    | Some p' => p' == p
    | None => true
    end.

  Definition req_new (_ : bool) : dist ReqSt_t :=
    {code k ← sample uniform (2 ^ req_key_bits) ;; ret (k, (emptym, emptym))}.

  Definition req_absent (a : ReqArg_t) : ReqRes_t :=
    match a with
    | inl _ => inl None
    | inr _ => inr None
    end.

  Definition req_query (b : bool) (s : ReqSt_t) (a : ReqArg_t) : dist (chProd ReqSt_t ReqRes_t) :=
    {code
      match a with
      | inl q =>
          if fresh_nonce s.2.1 (q.1, q.2.1) q.2.2 then
            let x := seal_req s.1 q.1 q.2.1 q.2.2 in
            ret ((s.1, (setm s.2.1 (q.1, q.2.1) q.2.2,
                        if b then s.2.2 else setm s.2.2 (q.1, (q.2.1, x)) q.2.2)),
                 inl (Some x))
          else ret (s, inl None)
      | inr y =>
          if b then ret (s, inr (open_req s.1 y.1 y.2.1 y.2.2))
          else ret (s, inr (s.2.2 y))
      end
    }.

  #[local] Notation I_multi_r := (I_multi ReqArg_t ReqRes_t).
  #[local] Notation MULTI_r q := (MULTI ReqSt_t ReqArg_t ReqRes_t q req_new req_query req_absent).
  #[local] Notation SINGLE_r := (SINGLE ReqSt_t ReqArg_t ReqRes_t req_new req_query req_absent).
  #[local] Notation HYB_r q := (HYB ReqSt_t ReqArg_t ReqRes_t q req_new req_query req_absent).
  #[local] Notation imap_r := (imap_loc ReqSt_t).

  Definition W_req : package I_multi_r I_req :=
    [package emptym ;
      #def #[ NEW_CHAN ] (_ : 'unit) : 'nat {
        #import {sig #[ NEWI ] : 'unit → 'nat} as newi ;;
        i ← newi Datatypes.tt ;;
        ret i
      } ;
      #def #[ SEAL_REQ ] (q : 'ch(SealIn)) : 'ch(chOption ReqSealed_t) {
        #import {sig #[ QUERYI ] : 'ch(chProd 'nat ReqArg_t) → 'ch(ReqRes_t)} as queryi ;;
        r ← queryi (q.1, inl q.2) ;;
        ret (match r with inl o => o | _ => None end)
      } ;
      #def #[ OPEN_REQ ] (x : 'ch(Packet)) : 'ch(chOption ReqPayload_t) {
        #import {sig #[ QUERYI ] : 'ch(chProd 'nat ReqArg_t) → 'ch(ReqRes_t)} as queryi ;;
        r ← queryi (x.1, inr x.2) ;;
        ret (match r with inr o => o | _ => None end)
      }
    ].

  Definition rbound_loc : Location := mkloc 141 (0%N : 'nat).

  Definition BoundReq (q : nat) : package I_req I_req :=
    [package [fmap rbound_loc] ;
      #def #[ NEW_CHAN ] (_ : 'unit) : 'nat {
        #import {sig #[ NEW_CHAN ] : 'unit → 'nat} as new_chan ;;
        c ← get rbound_loc ;;
        if (c < q)%N then
          i ← new_chan Datatypes.tt ;;
          #put rbound_loc := c.+1 ;;
          ret i
        else ret c
      } ;
      #def #[ SEAL_REQ ] (x : 'ch(SealIn)) : 'ch(chOption ReqSealed_t) {
        #import {sig #[ SEAL_REQ ] : 'ch(SealIn) → 'ch(chOption ReqSealed_t)} as seal ;;
        r ← seal x ;;
        ret r
      } ;
      #def #[ OPEN_REQ ] (x : 'ch(Packet)) : 'ch(chOption ReqPayload_t) {
        #import {sig #[ OPEN_REQ ] : 'ch(Packet) → 'ch(chOption ReqPayload_t)} as open ;;
        r ← open x ;;
        ret r
      }
    ].

  Definition req_keys (K : seq Key) (M : chMap 'nat ReqSt_t) : Prop :=
    ∀ i, match M i with
         | Some st => (i < size K)%N ∧ st.1 = nth no_key K i
         | None => (size K <= i)%N
         end.

  Definition req_nonces (N : chMap (ReqNonce_t ReqHdr_t ReqCookie_t) ReqPayload_t)
    (M : chMap 'nat ReqSt_t) : Prop :=
    ∀ i hc, match M i with
            | Some st => st.2.1 hc = N (i, hc)
            | None => N (i, hc) = None
            end.

  Definition req_sealed (T : chMap Packet ReqPayload_t) (M : chMap 'nat ReqSt_t) : Prop :=
    ∀ i y, match M i with
           | Some st => st.2.2 y = T (i, y)
           | None => T (i, y) = None
           end.

  Lemma req_keys_some K M i st : req_keys K M → M i = Some st → (i < size K)%N ∧ st.1 = nth no_key K i.
  Proof. move=> H E; move: (H i); by rewrite E. Qed.

  Lemma req_keys_none K M i : req_keys K M → M i = None → (size K <= i)%N.
  Proof. move=> H E; move: (H i); by rewrite E. Qed.

  Lemma req_keys_fresh K M : req_keys K M → M (size K) = None.
  Proof. move=> H; case E: (M (size K)) => [st|] //; move: (H (size K)); by rewrite E ltnn => -[]. Qed.

  Lemma req_keys_new K M k x : req_keys K M → req_keys (rcons K k) (setm M (size K) (k, x)).
  Proof.
    move=> H i; rewrite setmE size_rcons.
    case E: (i == size K)%B.
    - move/eqP: E => ->; by rewrite ltnSn nth_rcons ltnn eqxx.
    - move: (H i); case: (M i) => [st|].
      + move=> [Hi Hk]; by rewrite nth_rcons Hi ltnW.
      + move=> Hi; by rewrite ltn_neqAle eq_sym E Hi.
  Qed.

  Lemma req_keys_upd K M i st st' : req_keys K M → M i = Some st → st'.1 = st.1 →
    req_keys K (setm M i st').
  Proof.
    move=> H E E1 j; rewrite setmE; case F: (j == i)%B; last exact: H.
    move/eqP: F => ->; rewrite E1; move: (H i); by rewrite E.
  Qed.

  Lemma req_nonces_new N K M k x : req_keys K M → req_nonces N M →
    req_nonces N (setm M (size K) (k, (emptym, x))).
  Proof.
    move=> Hk Ht i hc; rewrite setmE; case E: (i == size K)%B; last exact: Ht.
    move/eqP: E => ->; move: (Ht (size K) hc); rewrite (req_keys_fresh _ _ Hk) /= emptymE.
    by move=> ->.
  Qed.

  Lemma req_nonces_upd N M i st st' : req_nonces N M → M i = Some st → st'.2.1 = st.2.1 →
    req_nonces N (setm M i st').
  Proof.
    move=> H E E1 j hc; rewrite setmE; case F: (j == i)%B; last exact: H.
    move/eqP: F => ->; rewrite E1; move: (H i hc); by rewrite E.
  Qed.

  Lemma req_nonces_seal N M i st hc p x : req_nonces N M → M i = Some st →
    req_nonces (setm N (i, hc) p) (setm M i (st.1, (setm st.2.1 hc p, x))).
  Proof.
    move=> H E j hc'; rewrite !setmE; case F: (j == i)%B => /=.
    - move/eqP: F => ->; move: (H i hc'); rewrite E => <-.
      rewrite setmE; case E2: (hc' == hc)%B; case E3: ((i, hc') == (i, hc))%B => //.
      + move/eqP: E2 => E2; subst; by rewrite eqxx in E3.
      + move/eqP: E3 => [] E4; subst; by rewrite eqxx in E2.
    - move: (H j hc'); case: (M j) => [st'|] ->;
      by rewrite xpair_eqE F.
  Qed.

  Lemma req_sealed_new T K M k x : req_keys K M → req_sealed T M →
    req_sealed T (setm M (size K) (k, (x, emptym))).
  Proof.
    move=> Hk Ht i y; rewrite setmE; case E: (i == size K)%B; last exact: Ht.
    move/eqP: E => ->; move: (Ht (size K) y); rewrite (req_keys_fresh _ _ Hk) /= emptymE.
    by move=> ->.
  Qed.

  Lemma req_sealed_upd T M i st st' : req_sealed T M → M i = Some st → st'.2.2 = st.2.2 →
    req_sealed T (setm M i st').
  Proof.
    move=> H E E1 j y; rewrite setmE; case F: (j == i)%B; last exact: H.
    move/eqP: F => ->; rewrite E1; move: (H i y); by rewrite E.
  Qed.

  Lemma req_sealed_seal T M i st y p x : req_sealed T M → M i = Some st →
    req_sealed (setm T (i, y) p) (setm M i (st.1, (x, setm st.2.2 y p))).
  Proof.
    move=> H E j y'; rewrite !setmE; case F: (j == i)%B => /=.
    - move/eqP: F => ->; move: (H i y'); rewrite E => <-.
      rewrite setmE; case E2: (y' == y)%B; case E3: ((i, y') == (i, y))%B => //.
      + move/eqP: E2 => E2; subst; by rewrite eqxx in E3.
      + move/eqP: E3 => [] E4; subst; by rewrite eqxx in E2.
    - move: (H j y'); case: (M j) => [st'|] ->;
      by rewrite xpair_eqE F.
  Qed.

  Lemma fresh_nonce_agree N M i st h c p :
    req_nonces N M → M i = Some st →
    fresh_nonce st.2.1 (h, c) p = sealed_once ReqHdr_t ReqCookie_t ReqPayload_t N (i, (h, c)) p.
  Proof. move=> H E; rewrite /fresh_nonce /sealed_once; move: (H i (h, c)); by rewrite E => ->. Qed.


  #[local] Notation icount_r := (icount_loc).

  Notation inv_req_real :=
    (heap_ignore [fmap rbound_loc ; rkeys ; rnonce ; icount_r ; imap_r] ⋊
     couple_cross rbound_loc icount_r eq ⋊
     couple_lhs rbound_loc rkeys (λ (c : 'nat) (K : seq Key), size K = c) ⋊
     couple_cross rkeys imap_r req_keys ⋊
     couple_cross rnonce imap_r req_nonces ⋊
     rel_app [:: (rhs, imap_r)] (req_sealed emptym)).

  Ltac req_close HM :=
    let H := fresh "H" in
    move=> H; first [ by apply: (req_keys_upd _ _ _ _ _ H HM)
                    | by apply: (req_nonces_upd _ _ _ _ _ H HM)
                    | by apply: (req_nonces_seal _ _ _ _ _ _ _ H HM)
                    | by apply: (req_sealed_upd _ _ _ _ _ H HM)
                    | by apply: (req_sealed_seal _ _ _ _ _ _ _ H HM) ].

  Lemma bound_req_real_is_multi q :
    (BoundReq q ∘ ReqReal)%pack ≈₀ (W_req ∘ MULTI_r q true)%pack.
  Proof.
    eapply eq_rel_perf_ind with inv_req_real.
    { ssprove_invariant.
      all: rewrite /rel_empty /heap_init /=.
      all: try done.
      all: by move=> *; rewrite !emptymE. }
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    all: cbv zeta.
    - apply: r_get_remember_lhs => c.
      apply: r_get_remember_rhs => c'.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 4%N => Ec. subst c'.
      case Hcq: (c < q)%N => /=; last first.
      { ssprove_forget_all. by apply: r_ret. }
      ssprove_swap_lhs 0%N.
      apply: r_get_remember_lhs => K.
      ssprove_rem_rel 3%N => Hsz.
      ssprove_rem_rel 2%N => Hk.
      subst c.
      ssprove_sync => k.
      apply: r_put_lhs. apply: r_put_lhs. apply: r_put_rhs. apply: r_put_rhs.
      ssprove_restore_mem.
      + ssprove_invariant.
        * by move=> _; rewrite size_rcons.
        * exact: req_keys_new.
        * move=> H; exact: req_nonces_new Hk H.
        * move=> H; exact: req_sealed_new Hk H.
      + by apply: r_ret.
    - case: x => i [h [c p]] /=.
      apply: r_get_remember_lhs => K.
      apply: r_get_remember_lhs => N.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 2%N => Hk.
      ssprove_rem_rel 1%N => Hn.
      case HM: (M i) => [st|] /=.
      + have [Hi Hst] := req_keys_some _ _ _ _ Hk HM.
        rewrite Hi /= -(fresh_nonce_agree _ _ _ _ _ _ _ Hn HM).
        case Hf: (fresh_nonce st.2.1 (h, c) p) => /=.
        * apply: r_put_lhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant. all: req_close HM.
          -- apply: r_ret => s0 s1 Hinv; split => //; by rewrite Hst.
        * apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant. all: req_close HM.
          -- by apply: r_ret.
      + have Hi := req_keys_none _ _ _ Hk HM.
        rewrite ltnNge Hi /=.
        ssprove_forget_all.
        by apply: r_ret.
    - case: x => i y /=.
      apply: r_get_remember_lhs => K.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 2%N => Hk.
      case HM: (M i) => [st|] /=.
      + have [Hi Hst] := req_keys_some _ _ _ _ Hk HM.
        rewrite Hi /=.
        apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant. all: req_close HM.
        * apply: r_ret => s0 s1 Hinv; split => //; by rewrite Hst.
      + have Hi := req_keys_none _ _ _ Hk HM.
        rewrite ltnNge Hi /=.
        ssprove_forget_all.
        by apply: r_ret.
  Qed.

  Notation inv_req_ideal :=
    (heap_ignore [fmap rbound_loc ; rkeys ; rnonce ; rsealed ; icount_r ; imap_r] ⋊
     couple_cross rbound_loc icount_r eq ⋊
     couple_lhs rbound_loc rkeys (λ (c : 'nat) (K : seq Key), size K = c) ⋊
     couple_cross rkeys imap_r req_keys ⋊
     couple_cross rnonce imap_r req_nonces ⋊
     couple_cross rsealed imap_r req_sealed).

  Lemma bound_req_ideal_is_multi q :
    (BoundReq q ∘ ReqIdeal)%pack ≈₀ (W_req ∘ MULTI_r q false)%pack.
  Proof.
    eapply eq_rel_perf_ind with inv_req_ideal.
    { ssprove_invariant.
      all: rewrite /rel_empty /heap_init /=.
      all: try done.
      all: by move=> *; rewrite !emptymE. }
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    all: cbv zeta.
    - apply: r_get_remember_lhs => c.
      apply: r_get_remember_rhs => c'.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 4%N => Ec. subst c'.
      case Hcq: (c < q)%N => /=; last first.
      { ssprove_forget_all. by apply: r_ret. }
      ssprove_swap_lhs 0%N.
      apply: r_get_remember_lhs => K.
      ssprove_rem_rel 3%N => Hsz.
      ssprove_rem_rel 2%N => Hk.
      subst c.
      ssprove_sync => k.
      apply: r_put_lhs. apply: r_put_lhs. apply: r_put_rhs. apply: r_put_rhs.
      ssprove_restore_mem.
      + ssprove_invariant.
        * by move=> _; rewrite size_rcons.
        * exact: req_keys_new.
        * move=> H; exact: req_nonces_new Hk H.
        * move=> H; exact: req_sealed_new Hk H.
      + by apply: r_ret.
    - case: x => i [h [c p]] /=.
      apply: r_get_remember_lhs => K.
      apply: r_get_remember_lhs => N.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 2%N => Hk.
      ssprove_rem_rel 1%N => Hn.
      case HM: (M i) => [st|] /=.
      + have [Hi Hst] := req_keys_some _ _ _ _ Hk HM.
        rewrite Hi /= -(fresh_nonce_agree _ _ _ _ _ _ _ Hn HM).
        case Hf: (fresh_nonce st.2.1 (h, c) p) => /=.
        * ssprove_swap_lhs 0%N.
          apply: r_get_remember_lhs => T.
          rewrite -Hst.
          apply: r_put_lhs. apply: r_put_lhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant. all: req_close HM.
          -- by apply: r_ret.
        * apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant. all: req_close HM.
          -- by apply: r_ret.
      + have Hi := req_keys_none _ _ _ Hk HM.
        rewrite ltnNge Hi /=.
        ssprove_forget_all.
        by apply: r_ret.
    - case: x => i y /=.
      apply: r_get_remember_lhs => K.
      apply: r_get_remember_rhs => M.
      ssprove_rem_rel 2%N => Hk.
      case HM: (M i) => [st|] /=.
      + have [Hi Hst] := req_keys_some _ _ _ _ Hk HM.
        rewrite Hi /=.
        apply: r_get_remember_lhs => T.
        ssprove_rem_rel 0%N => Hs.
        have -> : T (i, y) = st.2.2 y by move: (Hs i y); rewrite HM.
        apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant. all: req_close HM.
        * by apply: r_ret.
      + have Hi := req_keys_none _ _ _ Hk HM.
        rewrite ltnNge Hi /=.
        ssprove_forget_all.
        by apply: r_ret.
  Qed.


  Theorem req_single_instance q LA A :
    ValidPackage LA I_req A_export A →
    fseparate LA [fmap rbound_loc] →
    fseparate LA [fmap rkeys ; rnonce] →
    fseparate LA [fmap rkeys ; rnonce ; rsealed] →
    fseparate LA [fmap imap_r ; icount_r] →
    fseparate LA [fmap hmap_loc ReqSt_t ; hcount_loc] →
    fseparate LA [fmap single_loc ReqSt_t] →
    AdvantageE (BoundReq q ∘ ReqReal)%pack (BoundReq q ∘ ReqIdeal)%pack A
    <= \sum_(j < q) AdvantageE (SINGLE_r true) (SINGLE_r false) ((A ∘ W_req) ∘ HYB_r q j)%pack.
  Proof.
    move=> VA S0 S1 S1' S2 S3 S4.
    ssprove triangle (BoundReq q ∘ ReqReal)%pack [::
      (W_req ∘ MULTI_r q true)%pack ;
      (W_req ∘ MULTI_r q false)%pack
    ] (BoundReq q ∘ ReqIdeal)%pack A as ineq.
    eapply Order.POrderTheory.le_trans; first exact: ineq.
    have Z1 : AdvantageE (BoundReq q ∘ ReqReal)%pack (W_req ∘ MULTI_r q true)%pack A = 0.
    { apply: bound_req_real_is_multi.
      - apply: fseparateUr; [ exact: S0 | exact: S1 ].
      - apply: fseparateUr; [ exact: fseparatem0 | exact: S2 ]. }
    have Z2 : AdvantageE (BoundReq q ∘ ReqIdeal)%pack (W_req ∘ MULTI_r q false)%pack A = 0.
    { apply: bound_req_ideal_is_multi.
      - apply: fseparateUr; [ exact: S0 | exact: S1' ].
      - apply: fseparateUr; [ exact: fseparatem0 | exact: S2 ]. }
    rewrite Z1 [AdvantageE (W_req ∘ MULTI_r q false)%pack _ _]Advantage_sym Z2 add0r addr0.
    rewrite -Advantage_link.
    have VA' : ValidPackage (unionm LA emptym) I_multi_r A_export (A ∘ W_req)%pack.
    { ssprove_valid. }
    have T2 : fseparate (unionm LA emptym) [fmap imap_r ; icount_r].
    { apply: fseparateUl; [ exact: S2 | exact: fseparate0m ]. }
    have T3 : fseparate (unionm LA emptym) [fmap hmap_loc ReqSt_t ; hcount_loc].
    { apply: fseparateUl; [ exact: S3 | exact: fseparate0m ]. }
    have T4 : fseparate (unionm LA emptym) [fmap single_loc ReqSt_t].
    { apply: fseparateUl; [ exact: S4 | exact: fseparate0m ]. }
    exact: (multi_instance_hybrid_sum ReqSt_t ReqArg_t ReqRes_t q req_new req_query req_absent
              (unionm LA emptym) (A ∘ W_req)%pack VA' T2 T3 T4).
  Qed.

End ReqHybrid.
