st::StackTrace();
StackTrace(ACTION RETURN, ABRT);
StackTrace(ACTION RAISE, URG);
StackTrace(ACTION RAISE, SEGV);

foo::Script(print "starting...",
            wait 1,
            print "raising SIGABRT w/ action RETURN... (should ignore)",
            write st.signal ABRT,
            print "done!",
            wait 1,
            print "raising SIGURG w/ action RAISE... (should ignore)",
            write st.signal URG,
            print "done!",
            wait 1,
            print "raising SIGSEGV w/ action RAISE... (should coredump)",
            write st.signal SEGV,
            print "done!");
