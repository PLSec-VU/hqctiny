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

From SSProveHQC Require Import Tuple HQC.

Module Type HQCLetheParams.
  Include HQCParams.

  Parameter moduli : seq {poly 'F_2}.
  Parameter moduli_nonconstant : all (fun f : {poly 'F_2} => (1 < size f)%N) moduli.
  Parameter moduli_coprime : pairwise (@coprimep 'F_2) moduli.
  Parameter moduli_cover :
    (2 * n - 1 <= sumn (map (fun f : {poly 'F_2} => (size f).-1) moduli))%N.
End HQCLetheParams.

Module HQCLethe (P : HQCLetheParams).
  Include P.

  Module HQC_Sec := HQC_Security P.
  Import HQC_Sec.

  Definition fin_to_poly (d : nat) (i : 'fin (expn 2 d)) : {poly 'F_2} :=
    polyF2_of_nat (nat_of_ord i) 0 d.

  Definition poly_to_fin (d : nat) (p : {poly 'F_2}) : 'fin (expn 2 d) :=
    Ordinal (nat_of_polyF2_bound p d).

  Definition residue_of_nat (x : nat) : {poly 'F_2} := polyF2_of_nat x 0 x.

  Definition nat_of_residue (p : {poly 'F_2}) : nat := nat_of_polyF2 p 0 (size p).

  Definition residues_match (s : {poly 'F_2}) (ss : seq nat) : bool :=
    all2 (fun f x => (residue_of_nat x == s %% f)%B) moduli ss.

  Definition cut_residues (U : {poly 'F_2}) : seq nat :=
    [seq nat_of_residue (U %% f) | f <- moduli].

  Definition valid_residues (ss : seq nat) : bool :=
    [exists x : 'I_(2 ^ n), residues_match (fin_to_poly n x) ss].

  Definition crt_witness (ss : seq nat) : option 'I_(2 ^ n) :=
    [pick x : 'I_(2 ^ n) | residues_match (fin_to_poly n x) ss].

  Definition server_reply (f s_i r2 e m mu tau : {poly 'F_2}) : nat :=
    nat_of_residue
      ((m + s_i * (r2 %% f) + e + mu * Ring.gen + 'X ^+ n1n2 * tau) %% f).

  Definition server_replies (ss : seq nat) (r2 e m mu tau : {poly 'F_2})
    : seq nat :=
    [seq server_reply f (residue_of_nat x) r2 e m mu tau
    | '(f, x) <- zip moduli ss].

  Definition mu_bits := (n - 1)%N.
  Definition tau_bits := (n - n1n2)%N.

  Notation " 'ch ( x ) " := x (in custom pack_type at level 2, x constr).
  Notation " 'ch ( x ) " := x (at level 2) : package_scope.

  Definition Residues_t := chList chNat.
  Definition Request_t := chProd Rq_ct (chProd Residues_t Message_t).
  Definition Reply_t := chProd Rq_ct Residues_t.

  Definition HQCLETHE_ENC : ident := 0%N.

  Definition I_hqclethe_encrypt : Interface :=
    [interface
      #val #[ HQCLETHE_ENC ] : 'ch(Request_t) → 'ch(Reply_t)
    ].

  Definition hqclethe_encrypt : package emptym I_hqclethe_encrypt :=
    [package emptym ;
      #def #[ HQCLETHE_ENC ] (args : 'ch(Request_t)) : 'ch(Reply_t) {
        let '(h_fin, (ss, msg)) := args in
        if valid_residues ss then
          t_fin ← sample uniform ('C(n, we) ^ 3) ;;
          mu_fin ← sample uniform (2 ^ mu_bits) ;;
          tau_fin ← sample uniform (2 ^ tau_bits) ;;
          let '(r1_fin, r2_fin, e_fin) := split_fin3 t_fin in
          let r1 := \val (fin_to_rq_we r1_fin) in
          let r2 := \val (fin_to_rq_we r2_fin) in
          let e  := \val (fin_to_rq_we e_fin) in
          let h := fin_to_rq h_fin in
          let m := (P.encode msg : {poly 'F_2}) in
          ret (rq_to_fin (r1 + h * r2),
               server_replies ss r2 e m
                 (fin_to_poly mu_bits mu_fin) (fin_to_poly tau_bits tau_fin))
        else
          fail
      }
    ].

  Definition Sim : package HQC_Sec.I_hqc_encrypt I_hqclethe_encrypt :=
    [package emptym ;
      #def #[ HQCLETHE_ENC ] (args : 'ch(Request_t)) : 'ch(Reply_t) {
        #import {sig #[ HQC_Sec.HQC_ENC ] : 'ch(chProd HQC_Sec.PublicKey_t HQC_Sec.Message_t) → 'ch(HQC_Sec.Ciphertext_t)} as HQC_enc_oracle ;;
        let '(h_fin, (ss, msg)) := args in
        match crt_witness ss with
        | Some s_fin =>
          c ← HQC_enc_oracle ((h_fin, s_fin), msg) ;;
          mu_fin ← sample uniform (2 ^ mu_bits) ;;
          tau_fin ← sample uniform (2 ^ tau_bits) ;;
          let v := fin_to_poly n c.2 in
          ret (c.1,
               cut_residues (v + 'X ^+ n1n2 * fin_to_poly tau_bits tau_fin
                               + fin_to_poly mu_bits mu_fin * Ring.gen))
        | None => fail
        end
      }
    ].

  Lemma size_Rq_val (x : Ring.Rq) : (size (x : {poly 'F_2}) <= n)%N.
  Proof.
    have := size_npoly x.
    have Hsz : (size (mk_monic Ring.gen) = n.+1)%N by exact: Ring.size_mk_monic_gen.
    move=> H. apply: leq_trans H _. by rewrite Hsz.
  Qed.


  Lemma prime2_proof : prime 2.
  Proof. apply/primeP; split; first done. move=> d0 Hd0. case: d0 Hd0 => [|[|[|d0]]] //=. Qed.

  Lemma fin_to_poly_rq_to_fin : forall (X : Ring.Rq),
    fin_to_poly n (rq_to_fin X) = (X : {poly 'F_2}).
  Proof.
    intros. rewrite /fin_to_poly /rq_to_fin /= polyF2_takeK. apply: take_poly_id.
    move: (size_npoly X) => Hsize. apply: (leq_trans Hsize).
    rewrite Ring.size_mk_monic_gen. exact: leqnn.
  Qed.

  Lemma f_general_inv : forall (d : nat) (q : {poly 'F_2}) (x : 'fin (expn 2 d)),
    poly_to_fin d (fin_to_poly d (poly_to_fin d (fin_to_poly d x + q)) + q) = x.
  Proof.
    intros d q x. apply: val_inj => /=.
    rewrite /fin_to_poly /poly_to_fin /= polyF2_takeK take_polyD.
    rewrite take_poly_id.
    - move: (size_polyF2_of_nat x 0 d). by rewrite add0n.
    - have H_take_drop: take_poly d q + q = drop_poly d q * 'X^d.
      { apply/polyP => i. rewrite !coefE. case: ltnP => Hi.
        - rewrite GRing.addrC. by apply: addrr_pchar2; exact: (pchar_Fp prime2_proof).
        - by rewrite GRing.add0r (ssrnat.subnK Hi). }
      rewrite -addrA H_take_drop GRing.addrC.
      have H_add_scale: forall p r, nat_of_polyF2 (p * 'X^d + r) 0 d = nat_of_polyF2 r 0 d.
      { intros. apply: nat_of_polyF2_add_poly. move=> i Hi. by rewrite coefE Hi. }
      rewrite H_add_scale (nat_of_polyF2_of_nat x 0 d).
      + exact: ltn_ord.
      + by rewrite expn0 muln1.
  Qed.



  Lemma in_qpoly_rq_eq3 (a b c d' : Ring.Rq) :
    ((a + b * c + d') : {poly 'F_2})
    = (in_qpoly Ring.gen ((a : {poly 'F_2}) + (b : {poly 'F_2})
        * (c : {poly 'F_2}) + (d' : {poly 'F_2})) : {poly 'F_2}).
  Proof.
    apply/val_inj => /=.
    set m := mk_monic Ring.gen.
    have Hm_monic : m \is monic by rewrite /m; apply: monic_mk_monic.
    have sz_lt_m : forall (x : Ring.Rq), (size (x : {poly 'F_2}) < size m)%N.
    { move=> x. apply: (leq_ltn_trans (size_Rq_val x)).
      rewrite /m Ring.size_mk_monic_gen. exact: ltnSn. }
    rewrite -!(Pdiv.IdomainMonic.modpE (q := m) Hm_monic) //.
    rewrite !modpD.
    rewrite (modp_small (sz_lt_m a)).
    rewrite (modp_small (sz_lt_m d')).
    reflexivity.
  Qed.


  Lemma fin_to_poly_to_fin (d0 : nat) (p : {poly 'F_2}) :
    (size p <= d0)%N -> fin_to_poly d0 (poly_to_fin d0 p) = p.
  Proof.
    move=> Hsz.
    rewrite /fin_to_poly /poly_to_fin /= polyF2_takeK.
    exact: take_poly_id.
  Qed.

  Lemma poly_to_fin_fin_to_poly d0 (i : 'I_(2 ^ d0)) :
    poly_to_fin d0 (fin_to_poly d0 i) = i.
  Proof.
    apply/val_inj => /=.
    by rewrite nat_of_polyF2_of_nat // muln1.
  Qed.

  Definition f_mu (P : {poly 'F_2}) (k : 'I_(2 ^ mu_bits)) : 'I_(2 ^ mu_bits) :=
    poly_to_fin mu_bits (fin_to_poly mu_bits k + P %/ Ring.gen).

  Definition f_tau (P : {poly 'F_2}) (t : 'I_(2 ^ tau_bits)) : 'I_(2 ^ tau_bits) :=
    poly_to_fin tau_bits (fin_to_poly tau_bits t + drop_poly n1n2 (P %% Ring.gen)).

  Lemma f_mu_bij P : bijective (f_mu P).
  Proof.
    apply: (Bijective (g := f_mu P)); intro x;
      exact: (f_general_inv mu_bits (P %/ Ring.gen) x).
  Qed.

  Lemma f_tau_bij P : bijective (f_tau P).
  Proof.
    apply: (Bijective (g := f_tau P)); intro x;
      exact: (f_general_inv tau_bits (drop_poly n1n2 (P %% Ring.gen)) x).
  Qed.


  Lemma gen_neq0 : Ring.gen != 0.
  Proof. apply: monic_neq0; exact: Ring.gen_monic. Qed.

  Lemma mk_monic_gen : mk_monic Ring.gen = Ring.gen.
  Proof.
    have Hltn : (0 < n)%N by apply: (ltn_trans (n := 1)); [done | exact: n_gt1].
    rewrite /mk_monic Ring.size_gen Ring.gen_monic ltnS Hltn /=.
    by case: (lead_coef Ring.gen).
  Qed.

  Lemma divp_gen_eq (P : {poly 'F_2}) : P = P %/ Ring.gen * Ring.gen + P %% Ring.gen.
  Proof.
    exact: divp_eq.
  Qed.

  Lemma size_modp_gen (P : {poly 'F_2}) : (size (P %% Ring.gen)%R <= n)%N.
  Proof.
    have H : (size (P %% Ring.gen)%R < size Ring.gen)%N
      by rewrite ltn_modp; exact: gen_neq0.
    by rewrite Ring.size_gen in H.
  Qed.

  Lemma in_qpoly_val (P : {poly 'F_2}) :
    (in_qpoly Ring.gen P : {poly 'F_2}) = P %% Ring.gen.
  Proof.
    rewrite /= mk_monic_gen.
    by rewrite -Pdiv.IdomainMonic.modpE //; exact: Ring.gen_monic.
  Qed.

  Lemma fin_to_rq_val (i : 'I_(2 ^ n)) : (fin_to_rq i : {poly 'F_2}) = fin_to_poly n i.
  Proof.
    rewrite /fin_to_rq /fin_to_poly in_qpoly_val modp_small //.
    rewrite Ring.size_gen.
    exact: leq_ltn_trans (size_polyF2_of_nat _ 0 n) (ltnSn n).
  Qed.


  Lemma truncate_in_qpoly (P : {poly 'F_2}) :
    fin_to_poly n (rq_to_fin (truncate (in_qpoly Ring.gen P)))
    = take_poly n1n2 (P %% Ring.gen).
  Proof.
    rewrite fin_to_poly_rq_to_fin /truncate in_qpoly_val.
    have -> : \poly_(i < n1n2) (in_qpoly Ring.gen P : {poly 'F_2})`_i
              = take_poly n1n2 (P %% Ring.gen).
    { apply/polyP => j. by rewrite coef_poly coefE in_qpoly_val. }
    rewrite modp_small // Ring.size_gen.
    exact: leq_ltn_trans (size_take_poly _ _) (leq_ltn_trans n1n2_le_n (ltnSn n)).
  Qed.

  Lemma n_pred_add : ((n + n).-1 = n + mu_bits)%N.
  Proof.
    have Hn : (0 < n)%N by exact: ltn_trans (ltnSn 0) n_gt1.
    rewrite /mu_bits; move: Hn; case: n => // k _.
    by rewrite addSn addnS /= subn1 /=.
  Qed.

  Lemma size_cipher_poly (m s r2 e : {poly 'F_2}) :
    (size m <= n)%N -> (size s <= n)%N -> (size r2 <= n)%N -> (size e <= n)%N ->
    (size (m + s * r2 + e)%R <= n + mu_bits)%N.
  Proof.
    move=> Hm Hs Hr He.
    have Hn2 : (n <= (n + n).-1)%N by rewrite n_pred_add; exact: leq_addr.
    rewrite -n_pred_add.
    apply: leq_trans (size_polyD _ _) _; rewrite geq_max; apply/andP; split.
    - apply: leq_trans (size_polyD _ _) _; rewrite geq_max; apply/andP; split.
      + exact: leq_trans Hm Hn2.
      + apply: leq_trans (size_polyMleq _ _) _.
        rewrite -!subn1; exact: leq_sub2r (leq_add Hs Hr).
    - exact: leq_trans He Hn2.
  Qed.


  Lemma size_add_le (d0 : nat) (a b : {poly 'F_2}) :
    (size a <= d0)%N -> (size b <= d0)%N -> (size (a + b)%R <= d0)%N.
  Proof. by move=> Ha Hb; apply: leq_trans (size_polyD _ _) _; rewrite geq_max Ha. Qed.

  Lemma size_fin_to_poly d0 (i : 'I_(2 ^ d0)) : (size (fin_to_poly d0 i) <= d0)%N.
  Proof. by have := size_polyF2_of_nat i 0 d0; rewrite add0n. Qed.

  Lemma size_divp_gen (P : {poly 'F_2}) :
    (size P <= n + mu_bits)%N -> (size (P %/ Ring.gen)%R <= mu_bits)%N.
  Proof.
    move=> H.
    by rewrite size_divp ?gen_neq0 // Ring.size_gen /= leq_subLR.
  Qed.

  Lemma size_drop_mod_gen (P : {poly 'F_2}) :
    (size (drop_poly n1n2 (P %% Ring.gen)%R) <= tau_bits)%N.
  Proof.
    rewrite size_drop_poly /tau_bits; exact: leq_sub2r (size_modp_gen P).
  Qed.

  Lemma add_shuffle (V : zmodType) (a b c d T : V) :
    a + (T + d) + b + c = T + (c + d) + (b + a).
  Proof.
    rewrite !addrA [a + T]addrC [_ + b + c]addrAC [_ + d + c]addrAC.
    rewrite [_ + a + c]addrAC [_ + a + d]addrAC [_ + a + b]addrAC.
    by [].
  Qed.

  Lemma mask_identity (P : {poly 'F_2}) (mu : 'I_(2 ^ mu_bits))
    (tau : 'I_(2 ^ tau_bits)) :
    (size P <= n + mu_bits)%N ->
    P + fin_to_poly mu_bits mu * Ring.gen + 'X ^+ n1n2 * fin_to_poly tau_bits tau
    = take_poly n1n2 (P %% Ring.gen)
      + 'X ^+ n1n2 * fin_to_poly tau_bits (f_tau P tau)
      + fin_to_poly mu_bits (f_mu P mu) * Ring.gen.
  Proof.
    move=> HP.
    rewrite /f_mu /f_tau.
    have Emu : fin_to_poly mu_bits
        (poly_to_fin mu_bits (fin_to_poly mu_bits mu + P %/ Ring.gen))
        = fin_to_poly mu_bits mu + P %/ Ring.gen
      := fin_to_poly_to_fin _ _
           (size_add_le _ _ _ (size_fin_to_poly _ _) (size_divp_gen _ HP)).
    have Etau : fin_to_poly tau_bits
        (poly_to_fin tau_bits
          (fin_to_poly tau_bits tau + drop_poly n1n2 (P %% Ring.gen)))
        = fin_to_poly tau_bits tau + drop_poly n1n2 (P %% Ring.gen)
      := fin_to_poly_to_fin _ _
           (size_add_le _ _ _ (size_fin_to_poly _ _) (size_drop_mod_gen _)).
    rewrite Emu Etau.
    set q := P %/ Ring.gen.
    set Pq := P %% Ring.gen.
    have HP' : P = q * Ring.gen + Pq := divp_gen_eq P.
    have Htd := poly_take_drop n1n2 Pq.
    set T := take_poly n1n2 Pq.
    set D := drop_poly n1n2 Pq.
    rewrite {1}HP' -Htd -/T -/D.
    rewrite (mulrC D) [_ * (_ + D)]mulrDr [(_ + q) * _]mulrDl.
    exact: add_shuffle.
  Qed.


  Lemma modp_mul_both (f a b : {poly 'F_2}) :
    ((a %% f) * (b %% f)) %% f = (a * b) %% f.
  Proof. by rewrite modp_mul mulrC modp_mul mulrC. Qed.

  Lemma server_reply_eq (f s_i s r2 e m mu tau : {poly 'F_2}) :
    s_i = s %% f ->
    server_reply f s_i r2 e m mu tau
    = nat_of_residue ((m + s * r2 + e + mu * Ring.gen + 'X ^+ n1n2 * tau) %% f).
  Proof.
    move=> ->; rewrite /server_reply; congr nat_of_residue.
    by rewrite !modpD modp_mul_both.
  Qed.

  Lemma server_replies_cut (fs : seq {poly 'F_2}) (ss : seq nat)
    (s r2 e m mu tau : {poly 'F_2}) :
    all2 (fun f x => (residue_of_nat x == s %% f)%B) fs ss ->
    [seq server_reply f (residue_of_nat x) r2 e m mu tau | '(f, x) <- zip fs ss]
    = [seq nat_of_residue
         ((m + s * r2 + e + mu * Ring.gen + 'X ^+ n1n2 * tau) %% f) | f <- fs].
  Proof.
    elim: fs ss => [|f fs IH] [|x ss] //= => /andP[/eqP Hx Hall].
    by rewrite (server_reply_eq _ _ _ _ _ _ _ _ Hx) (IH _ Hall).
  Qed.

  Lemma server_replies_cut_residues ss s r2 e m mu tau :
    residues_match s ss ->
    server_replies ss r2 e m mu tau
    = cut_residues (m + s * r2 + e + mu * Ring.gen + 'X ^+ n1n2 * tau).
  Proof. exact: server_replies_cut. Qed.


  Lemma coprimep_big (f : {poly 'F_2}) (fs : seq {poly 'F_2}) :
    all (coprimep f) fs -> coprimep f (\prod_(g <- fs) g).
  Proof.
    elim: fs => [|g fs IH] /=; first by rewrite big_nil coprimep1.
    move=> /andP[Hg Hfs].
    by rewrite big_cons coprimepMr Hg IH.
  Qed.

  Lemma dvdp_big (fs : seq {poly 'F_2}) (a : {poly 'F_2}) :
    pairwise (@coprimep 'F_2) fs -> (forall f, f \in fs -> f %| a) ->
    \prod_(f <- fs) f %| a.
  Proof.
    elim: fs => [|f fs IH] /=; first by move=> _ _; rewrite big_nil dvd1p.
    move=> /andP[Hf Hfs] Hall.
    rewrite big_cons (Gauss_dvdp _ (coprimep_big f fs Hf)).
    rewrite (Hall f (mem_head f fs)) /=.
    apply: IH => // g Hg; apply: Hall; by rewrite in_cons Hg orbT.
  Qed.

  Lemma size_big (fs : seq {poly 'F_2}) :
    all (fun f : {poly 'F_2} => (1 < size f)%N) fs ->
    size (\prod_(f <- fs) f)
    = (sumn (map (fun f : {poly 'F_2} => (size f).-1) fs)).+1.
  Proof.
    elim: fs => [|f fs IH] /=; first by rewrite big_nil size_poly1.
    move=> /andP[Hf Hfs].
    have Hf0 : f != 0 by rewrite -size_poly_gt0 (ltn_trans _ Hf).
    have Hp0 : \prod_(g <- fs) g != 0.
    { by rewrite -size_poly_gt0 IH. }
    rewrite big_cons size_mul // IH //.
    by move: Hf; case: (size f) => // k _; rewrite addnS /= addSn.
  Qed.

  Definition moduli_prod : {poly 'F_2} := \prod_(f <- moduli) f.

  Lemma crt_injective (a b : {poly 'F_2}) :
    (size a <= 2 * n - 1)%N -> (size b <= 2 * n - 1)%N ->
    (forall f, f \in moduli -> a %% f = b %% f) -> a = b.
  Proof.
    move=> Ha Hb Hmod.
    have Hdvd : moduli_prod %| a - b.
    { apply: dvdp_big moduli_coprime _ => f Hf.
      apply/modp_eq0P.
      by rewrite modpD modpN Hmod ?subrr. }
    have Hsz : (size (a - b)%R < size moduli_prod)%N.
    { rewrite /moduli_prod (size_big _ moduli_nonconstant).
      rewrite ltnS.
      apply: leq_trans (size_polyD _ _) _; rewrite geq_max size_polyN.
      apply/andP; split; apply: leq_trans moduli_cover => //. }
    apply/eqP; rewrite -subr_eq0; apply/eqP.
    apply: contraTeq Hsz => Hne.
    by rewrite -leqNgt dvdp_leq.
  Qed.

  Lemma crt_witness_unique ss (x y : 'I_(2 ^ n)) :
    residues_match (fin_to_poly n x) ss ->
    residues_match (fin_to_poly n y) ss -> x = y.
  Proof.
    move=> Hx Hy.
    have Hsz (z : 'I_(2 ^ n)) : (size (fin_to_poly n z) <= 2 * n - 1)%N.
    { apply: leq_trans (size_fin_to_poly n z) _.
      have Hn : (0 < n)%N by exact: ltn_trans (ltnSn 0) n_gt1.
      rewrite mul2n -addnn (leq_subRL _ (leq_trans Hn (leq_addr n n))).
      exact: leq_add Hn (leqnn n). }
    have : fin_to_poly n x = fin_to_poly n y.
    { apply: crt_injective (Hsz x) (Hsz y) _ => f Hf.
      move: Hx Hy; rewrite /residues_match.
      elim: moduli ss Hf => [|g gs IH] [|z zs] //= Hf.
      move=> /andP[/eqP Hx1 Hx2] /andP[/eqP Hy1 Hy2].
      rewrite in_cons in Hf; case/orP: Hf => [/eqP ->|Hf].
      - by rewrite -Hx1 -Hy1.
      - exact: IH Hf Hx2 Hy2. }
    move=> /(f_equal (poly_to_fin n)).
    by rewrite !poly_to_fin_fin_to_poly.
  Qed.

  Lemma crt_witness_some ss s_fin :
    crt_witness ss = Some s_fin -> residues_match (fin_to_poly n s_fin) ss.
  Proof.
    rewrite /crt_witness; case: pickP => // x Hx [<-]; exact: Hx.
  Qed.

  Lemma crt_witness_none ss : crt_witness ss = None -> valid_residues ss = false.
  Proof.
    rewrite /crt_witness /valid_residues.
    case: pickP => // Hn _.
    apply/negbTE/existsP => -[x Hx].
    by move: (Hn x); rewrite Hx.
  Qed.

  Lemma crt_witness_valid ss s_fin :
    crt_witness ss = Some s_fin -> valid_residues ss.
  Proof.
    move/crt_witness_some => H.
    by apply/existsP; exists s_fin.
  Qed.

  Theorem hqclethe_indistinguishable :
    hqclethe_encrypt ≈₀ (Sim ∘ HQC_Sec.hqc_encrypt)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel m.
    destruct m as [h_fin [ss msg]].
    simplify_linking.
    case Ew: (crt_witness ss) => [s_fin|].
    - rewrite (crt_witness_valid _ _ Ew).
      simplify_linking.
      have Hmatch := crt_witness_some _ _ Ew.
      eapply r_uniform_bij.
      Unshelve. 3: exact (fun x => x).
      { exact: (@Bijective _ _ id id (fun x => erefl) (fun x => erefl)). }
      intro t_fin. simpl.
      pose r2 := sval (fin_to_rq_we (tnth (fin_to_tuple_fin 'C(n, we) 3 t_fin) (inord 1))).
      pose e := sval (fin_to_rq_we (tnth (fin_to_tuple_fin 'C(n, we) 3 t_fin) (inord 2))).
      pose m := (P.encode msg : {poly 'F_2}).
      pose s := fin_to_poly n s_fin.
      pose Pc := (m + s * r2 + e)%R.
      have HszP : (size Pc <= n + mu_bits)%N.
      { apply: size_cipher_poly; first [exact: size_Rq_val | exact: size_fin_to_poly]. }
      eapply r_uniform_bij.
      Unshelve. 3: exact (f_mu Pc).
      { apply: f_mu_bij. }
      intro mu_val. simpl.
      eapply r_uniform_bij.
      Unshelve. 3: exact (f_tau Pc).
      { apply: f_tau_bij. }
      intro tau_val. simpl.
      eapply r_ret.
      move=> s0 s1 ->. split; [ | done ].
      f_equal.
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
    - rewrite (crt_witness_none _ Ew).
      simplify_linking.
      apply: r_fail.
Qed.

End HQCLethe.

Module Type RingDegree.
  Parameter n : nat.
End RingDegree.

Module Type CRTModuli (H : RingDegree).
  Parameter moduli : seq {poly 'F_2}.
  Parameter moduli_nonconstant : all (fun f : {poly 'F_2} => (1 < size f)%N) moduli.
  Parameter moduli_coprime : pairwise (@coprimep 'F_2) moduli.
  Parameter moduli_cover :
    (2 * H.n - 1 <= sumn (map (fun f : {poly 'F_2} => (size f).-1) moduli))%N.
End CRTModuli.

Module HQCLetheFor (H : HQCParams) (M : CRTModuli H).
  Module Params <: HQCLetheParams.
    Include H.
    Include M.
  End Params.
  Include HQCLethe Params.
End HQCLetheFor.

Module HQCLethe1 (E : HQC1Encoding) (M : CRTModuli HQC1Consts).
  Module Base := HQC1 E.
  Include HQCLetheFor Base M.
End HQCLethe1.
Module HQCLethe3 (E : HQC3Encoding) (M : CRTModuli HQC3Consts).
  Module Base := HQC3 E.
  Include HQCLetheFor Base M.
End HQCLethe3.
Module HQCLethe5 (E : HQC5Encoding) (M : CRTModuli HQC5Consts).
  Module Base := HQC5 E.
  Include HQCLetheFor Base M.
End HQCLethe5.
