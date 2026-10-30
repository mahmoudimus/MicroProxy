----------------------------- MODULE TrafficKeys -----------------------------
EXTENDS Naturals, FiniteSets

\* A finite, post-handshake TLS 1.3 lifecycle abstraction. Epoch labels stand
\* for actual directional traffic keys; distinct HKDF output is an assumption.
CONSTANTS Cap, MaxEpoch, MaxFragments, ReuseWriteKey

ASSUME /\ Cap \in Nat /\ Cap >= 2
       /\ MaxEpoch \in Nat /\ MaxEpoch >= 1
       /\ MaxFragments \in Nat /\ MaxFragments >= 2
       /\ ReuseWriteKey \in BOOLEAN

Directions == {"write", "read"}
Epochs == 0..MaxEpoch
KeyIds == Directions \X Epochs
NonceIds == Directions \X Epochs \X (0..Cap)

VARIABLES st, previousClosed
vars == <<st, previousClosed>>

Init ==
    /\ st = [epoch |-> [d \in Directions |-> 0],
              seq |-> [d \in Directions |-> 0],
              closed |-> {}, bounded |-> {},
              wp |-> "Idle", rp |-> "Ready", origin |-> "None", left |-> 0,
              uses |-> [n \in NonceIds |-> 0],
              installed |-> {<<"write", 0>>, <<"read", 0>>},
              rejected |-> {}, dataKeys |-> {},
              io |-> FALSE, multi |-> FALSE, fragments |-> 0,
              badDataSequence |-> FALSE]
    /\ previousClosed = {}

\* cipher() increments before cipher initialization/doFinal/output. Count the
\* nonce attempt even when crypto or OutputStream.write subsequently fails.
Consume(t, d) ==
    [t EXCEPT !.seq[d] = @ + 1,
              !.uses[<<d, t.epoch[d], t.seq[d]>>] = @ + 1]

FinishWrite(t, ioFailure) ==
    LET done == [t EXCEPT !.wp = "Idle", !.left = 0, !.origin = "None",
                          !.fragments = 0, !.io = @ \/ ioFailure]
    IN IF t.origin = "Peer" THEN [done EXCEPT !.rp = "Ready"] ELSE done

\* fail()/closeWrite() try an alert under the currently active old key. The
\* exhausted() guard can prevent it; an output failure still consumes a nonce.
AlertAttempt(t) ==
    IF "write" \notin t.closed /\ t.seq["write"] < Cap
    THEN Consume(t, "write") ELSE t

Fail(t) ==
    [AlertAttempt(t) EXCEPT !.closed = Directions, !.wp = "Idle",
                            !.rp = "Ready", !.origin = "None", !.left = 0,
                            !.fragments = 0]

BeginWrite(n) ==
    /\ st.wp = "Idle"
    /\ "write" \notin st.closed \cup st.bounded
    /\ st' = [st EXCEPT !.wp = "Data", !.left = n,
                        !.origin = "App", !.fragments = 0]

ApplicationFragment(ok) ==
    /\ st.wp = "Data"
    /\ "write" \notin st.closed
    /\ st.seq["write"] < Cap - 1
    /\ LET used == Consume(st, "write")
           sent == [used EXCEPT
                     !.left = @ - 1,
                     !.fragments = @ + 1,
                     !.dataKeys = @ \cup {<<"write", st.epoch["write"]>>},
                     !.multi = @ \/ st.fragments > 0,
                     !.badDataSequence = @ \/ st.seq["write"] >= Cap - 1]
       IN st' = IF ~ok THEN FinishWrite(used, TRUE)
                ELSE IF st.left = 1 THEN FinishWrite(sent, FALSE) ELSE sent

\* The final old-key slot is reserved for the KeyUpdate record, including
\* between fragments of a single application write.
BeginAutomaticUpdate ==
    /\ st.wp = "Data"
    /\ st.seq["write"] >= Cap - 1
    /\ st' = [st EXCEPT !.wp = "KeyUpdate"]

SendKeyUpdate(ok) ==
    /\ st.wp = "KeyUpdate"
    /\ st.seq["write"] < Cap
    /\ LET used == Consume(st, "write")
       IN st' = IF ok THEN [used EXCEPT !.wp = "FlushUpdate"]
                ELSE FinishWrite(used, TRUE)

ExhaustedKeyUpdate ==
    /\ st.wp = "KeyUpdate"
    /\ st.seq["write"] >= Cap
    /\ st' = FinishWrite(st, TRUE)

FlushKeyUpdate(ok) ==
    /\ st.wp = "FlushUpdate"
    /\ st' = IF ok THEN [st EXCEPT !.wp = "Install"]
             ELSE FinishWrite(st, TRUE)

\* The policy decision is for the actual candidate key label (direction,N+1),
\* after successful old-key KeyUpdate output and flush, before assignment.
AcceptWriteKey ==
    /\ st.wp = "Install"
    /\ st.epoch["write"] < MaxEpoch
    /\ LET candidate == st.epoch["write"] + 1
           installedEpoch == IF ReuseWriteKey THEN st.epoch["write"] ELSE candidate
           installed == [st EXCEPT !.epoch["write"] = installedEpoch,
                                    !.seq["write"] = 0,
                                    !.installed = @ \cup {<<"write", installedEpoch>>}]
       IN st' = IF st.left > 0 THEN [installed EXCEPT !.wp = "Data"]
                ELSE FinishWrite(installed, FALSE)

RejectWriteKey ==
    /\ st.wp = "Install"
    /\ st.epoch["write"] < MaxEpoch
    /\ st' = Fail([st EXCEPT !.rejected = @ \cup {<<"write", st.epoch["write"] + 1>>}])

\* Explicit finite-prefix boundary, NOT a production close or rejection. No
\* transition that installs epoch MaxEpoch+1 is included in this model.
WriteEpochBoundary ==
    /\ st.wp = "Install"
    /\ st.epoch["write"] = MaxEpoch
    /\ st' = FinishWrite([st EXCEPT !.bounded = @ \cup {"write"}], FALSE)

CanRead == /\ st.rp = "Ready"
           /\ "read" \notin st.closed \cup st.bounded

ReceiveApplication ==
    /\ CanRead
    /\ st.seq["read"] < Cap
    /\ st' = [Consume(st, "read") EXCEPT
               !.dataKeys = @ \cup {<<"read", st.epoch["read"]>>}]

ReceiveKeyUpdate(request, accept) ==
    /\ CanRead
    /\ st.seq["read"] < Cap
    /\ LET used == Consume(st, "read")
           candidate == st.epoch["read"] + 1
       IN st' =
          IF st.epoch["read"] = MaxEpoch
          THEN [used EXCEPT !.bounded = @ \cup {"read"}]
          ELSE IF accept
               THEN [used EXCEPT !.epoch["read"] = candidate,
                                  !.seq["read"] = 0,
                                  !.installed = @ \cup {<<"read", candidate>>},
                                  !.rp = IF request THEN "Response" ELSE "Ready"]
               ELSE [used EXCEPT !.rejected = @ \cup {<<"read", candidate>>},
                                  !.rp = "Fail"]

\* The reader can accept keys while an application writer holds writeLock;
\* a requested response (or fail) waits for that complete write to release it.
RespondToPeer ==
    /\ st.rp = "Response" /\ st.wp = "Idle"
    /\ st' = IF "write" \in st.closed \cup st.bounded
             THEN [st EXCEPT !.rp = "Ready"]
             ELSE [st EXCEPT !.wp = "KeyUpdate", !.origin = "Peer",
                              !.left = 0, !.fragments = 0]

ReceiveBadRecord ==
    /\ CanRead /\ st.seq["read"] < Cap
    /\ st' = [Consume(st, "read") EXCEPT !.rp = "Fail"]

ReadLimitFailure ==
    /\ CanRead /\ st.seq["read"] >= Cap
    /\ st' = [st EXCEPT !.rp = "Fail"]

HandleReadFailure ==
    /\ st.rp = "Fail" /\ st.wp = "Idle"
    /\ st' = Fail(st)

\* Generic IOException is deliberately not equated with fail(QuicException).
\* An input failure before decryption does not even consume a record nonce.
ReadIOException ==
    /\ CanRead
    /\ st' = [st EXCEPT !.io = TRUE]

ReadEof ==
    /\ CanRead
    /\ st' = [st EXCEPT !.closed = @ \cup {"read"}]

ReceiveCloseNotify ==
    /\ CanRead /\ st.seq["read"] < Cap
    /\ st' = [Consume(st, "read") EXCEPT !.closed = @ \cup {"read"}]

CloseWrite ==
    /\ st.wp = "Idle" /\ "write" \notin st.closed
    /\ st' = [AlertAttempt(st) EXCEPT !.closed = @ \cup {"write"}]

Terminal == /\ st.wp = "Idle" /\ st.rp = "Ready"
            /\ st.closed \cup st.bounded = Directions
TerminalStutter == /\ Terminal /\ UNCHANGED st

Step == \/ \E n \in 1..MaxFragments : BeginWrite(n)
        \/ \E ok \in BOOLEAN : ApplicationFragment(ok)
        \/ BeginAutomaticUpdate
        \/ \E ok \in BOOLEAN : SendKeyUpdate(ok)
        \/ ExhaustedKeyUpdate
        \/ \E ok \in BOOLEAN : FlushKeyUpdate(ok)
        \/ AcceptWriteKey \/ RejectWriteKey \/ WriteEpochBoundary
        \/ ReceiveApplication
        \/ \E request, accept \in BOOLEAN : ReceiveKeyUpdate(request, accept)
        \/ RespondToPeer \/ ReceiveBadRecord \/ ReadLimitFailure
        \/ HandleReadFailure \/ ReadIOException \/ ReadEof
        \/ ReceiveCloseNotify \/ CloseWrite \/ TerminalStutter

\* previousClosed is an observer, not a guard or assumption on production
\* transitions. It detects any transition that reopens either direction.
Next == /\ Step /\ previousClosed' = st.closed
Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ st \in [epoch : [Directions -> Epochs], seq : [Directions -> 0..Cap],
                closed : SUBSET Directions, bounded : SUBSET Directions,
                wp : {"Idle", "Data", "KeyUpdate", "FlushUpdate", "Install"},
                rp : {"Ready", "Response", "Fail"}, origin : {"None", "App", "Peer"},
                left : 0..MaxFragments, uses : [NonceIds -> 0..2],
                installed : SUBSET KeyIds, rejected : SUBSET KeyIds,
                dataKeys : SUBSET KeyIds, io : BOOLEAN, multi : BOOLEAN,
                fragments : 0..MaxFragments, badDataSequence : BOOLEAN]
    /\ previousClosed \subseteq Directions

NoNonceReuse == \A n \in NonceIds : st.uses[n] <= 1
NonceEventsBelowCap == \A n \in NonceIds : st.uses[n] > 0 => n[3] < Cap
SequenceBounded == \A d \in Directions : st.seq[d] \in 0..Cap
NoRejectedKeyActive == \A d \in Directions : <<d, st.epoch[d]>> \notin st.rejected
NoRejectedKeyInstalled == st.installed \cap st.rejected = {}
NoDataOnRejectedKey == st.dataKeys \cap st.rejected = {}
FinalOldKeySlotReserved == ~st.badDataSequence
ClosedAbsorbing == previousClosed \subseteq st.closed

\* Expected-failure reachability check: a real counterexample must include two
\* successful fragments in one call, both key rotations, a generic I/O failure,
\* then an actual candidate rejection and fail closing both directions.
CoverageReached == /\ st.epoch["write"] > 0 /\ st.epoch["read"] > 0
                   /\ st.multi /\ st.io /\ st.rejected # {}
                   /\ st.closed = Directions
NoCoverageWitness == ~CoverageReached
=============================================================================
