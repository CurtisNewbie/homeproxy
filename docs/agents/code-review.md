# Code review rules: homeproxy

Mistakes this repo keeps making, each one a tell that shows up in a diff. Written by reviews;
empty until one finds a mistake here.

1. **A redirect on a state-changing request is not a write.** Tell: an `http.Client` used for `PUT`,
   `PATCH`, or `DELETE` with no `CheckRedirect`, or a test that asserts only the final status. Shape:
   `CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }`,
   so a `3xx` lands in the error branch and warns instead of being followed as a `GET`.
2. **A fake that never applies the mutation it asserts makes the test inert.** Tell: a handler
   returning `204`/`200` while the test then reads state the test itself set, or a `setNow`/`setState`
   call that changes nothing because the fake already held that value. Shape: the fake applies the
   request to its own state, and the test asserts a later observation of that change.
3. **An exact-count wait turns a hot loop into the wrong diagnosis.** Tell: waiting for `count == 1`
   on a counter the implementation may exceed. Shape: `count >= 1` for "it arrived", plus a separate
   assertion that the count stopped.
