From SSProveHQC Require Import HQC HQCLethe DerivedMasks SessionKey MaskPrimitives SessionKeyBoth Hybrid SessionKeyHybrid CookieIntegrity MLKEMCCA RequestIntegrity PuzzleKeys ActiveSecrecy ActivePuzzle HybridInst HybridApply.

Print Assumptions multi_to_single_instance.
Print Assumptions cookie_integrity.
Print Assumptions cca_from_standard.
Print Assumptions request_integrity.
Print Assumptions puzzle_key_separation.
Print Assumptions active_session_key_secrecy.
Print Assumptions active_session_key_secrecy_std.
Print Assumptions active_puzzle_hops.
Print Assumptions active_puzzle_session_key_secrecy.
Print Assumptions active_puzzle_session_key_secrecy_std.
Print Assumptions multi_instance_hybrid_sum.
Print Assumptions multi_instance_hybrid_bound.
Print Assumptions prf_single_instance.
Print Assumptions req_single_instance.

Module Check (E : HQC1Encoding) (M : CRTModuli HQC1Consts).
  Module L := HQCLethe1 E M.
  Print Assumptions L.hqclethe_indistinguishable.
  Module D := HQCLetheDerived1 E M.
  Print Assumptions D.seeded_masks_simulatable.
  Print Assumptions D.seeded_masks_simulatable_uniform_coins.
  Module S := HQCLetheSession1 E M.
  Print Assumptions S.session_key_secrecy.
  Print Assumptions S.overflow_masks_from_seed_masks.
  Module X := HQCLetheMaskPrimitives1 E M.
  Print Assumptions X.seed_masks_from_primitives.
  Module B := HQCLetheBoth1 E M.
  Print Assumptions B.session_key_secrecy_mlkem.
  Print Assumptions B.passive_secrecy_if_mlkem_holds.
  Print Assumptions B.passive_secrecy_if_hqc_holds.
  Print Assumptions B.passive_secrecy_unless_both_fall.
  Print Assumptions B.authkdf_single_instance.
  Module Y := HQCLetheSessionHybrid1 E M.
  Print Assumptions Y.kem_single_instance.
  Print Assumptions Y.masks_single_instance.
  Print Assumptions Y.kdf_single_instance.
  Print Assumptions Y.session_key_secrecy_single_instance.
End Check.
