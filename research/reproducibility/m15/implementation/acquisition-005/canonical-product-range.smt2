; benchmark generated from python API
(set-info :status unknown)
(declare-fun coefficient_b () Int)
(declare-fun coefficient_a () Int)
(assert
 (and (and (>= coefficient_a 0) (<= coefficient_a 7680)) (and (>= coefficient_b 0) (<= coefficient_b 7680))))
(assert
 (let ((?x396 (* coefficient_a coefficient_b)))
(let (($x306 (<= ?x396 58982400)))
(let (($x322 (and (>= ?x396 0) $x306)))
(not $x322)))))
(check-sat)
