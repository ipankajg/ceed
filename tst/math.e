/*
 * A helper function to show the concept of functions and global variables.
 * It prints value of global variable R, followed by a new line.
 */
_b {
    wi(R); nl();
}

/*
 * This is the entry point, equivalent to c main function.
 * It does simple calculation and stores result in global variable: R
 */
_a {
    nl();
    ws("-------------------------"); nl();
    ws("| Choice   Operation    |"); nl();
    ws("-------------------------"); nl();
    ws("|   1      Addition     |"); nl();
    ws("|   2      Substraction |"); nl();
    ws("|   0      Exit         |"); nl();
    ws("-------------------------"); nl();
    ws("Please enter your choice: ");
    x = ri();
    if (x == 1) {
        ws("Enter first number: ");
        a = ri();
        ws("Enter second number: ");
        b = ri();
        R = a + b;
        ws("Result: ");
        _b();
    } el {
        if (x == 2) {
            ws("Enter first number: ");
            a = ri();
            ws("Enter second number: ");
            b = ri();
            ws("Result: ");
            wi(a - b); nl();
        }
    }
}
