#!/usr/bin/perl
# CGI demo perl script taken from https://en.wikipedia.org/wiki/Common_Gateway_Interface

=head1 DESCRIPTION

printenv — a CGI program that just prints its environment

=cut
print "Content-type: text/plain\n\n";

for my $var ( sort keys %ENV ) {
 printf "%s = \"%s\"\n", $var, $ENV{$var};
}