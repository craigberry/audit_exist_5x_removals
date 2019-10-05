#!/usr/bin/env perl
use strict;
use warnings;
use File::Spec;
use File::Find;

# Copyright (C) 2019 Craig A. Berry
#    Released into the public domain.  Use at your own risk in any way you like,
#    but there are no warranties of any kind.

# Script to find functions and namespaces deprecated in eXist-db 4.x and removed
# in 5.x.  It scans all files whose names end in .xq, .xqm, or .xql in the directory
# tree supplied as an argument (or the current directory if none is supplied) for
# functions and namespaces being deprecated. It then reports its findings to
# standard output in a format similar to grep -H (file, line number, line contents).

# Usage:
#     perl audit_removals.pl topdir

# Caveats:
#    This is entirely line-based.  If code has a function name on one line and the
#    opening parenthesis on another line, it will be missed.
#
#    The script goes to rather extreme lengths to account for the fact that the
#    "fn:" prefix in "fn:map" is optional and that the word "map" appears in many
#    contexts that are not function calls.  Efforts to prevent false negatives and
#    false positives have not been 100% successful in previous versions of the
#    script, and there may well be some cases remaining.

# GitHub repo:
#    https://github.com/craigberry/audit_exist_5x_removals 

my %removed_funcs = (
    'map' => 'fn:for-each',                # leave off optional fn: namespace
    'map-pairs' => 'fn:for-each-pair',     # leave off optional fn: namespace
    'map:for-each-entry' => 'map:for-each',
    'map:new' => 'map:merge',
    'util:catch' => 'XQuery 3.1 try-catch expression',
    'util:eval-async' => 'none available -- long broken',
    'util:parse' => 'fn:parse-xml',
    'util:serialize' => 'fn:serialize',
    'validation:validate' => 'more specific validation function',
    'validation:validate-report' => 'more specific validation function',
    'xmldb:add-user-to-group' => 'sm:add-group-member',
    'xmldb:change-user' => 'more specific sm function',
    'xmldb:chmod-collection' => 'sm:chmod',
    'xmldb:chmod-resource' => 'sm:chmod',
    'xmldb:copy' => 'xmldb:copy-collection or xmldb:copy-resource (no replacement in 4.x.x!)',
    'xmldb:create-group' => 'sm:create-group',
    'xmldb:create-user' => 'sm:create-account',
    'xmldb:delete-user' => 'sm:remove-account',
    'xmldb:document' => 'fn:doc',
    'xmldb:exists-user' => 'sm:user-exists',
    'xmldb:get-current-user' => 'sm:id',
    'xmldb:get-current-user-attribute' => 'sm:get-account-metadata',
    'xmldb:get-current-user-attribute-names' => 'sm:get-account-metadata-keys',
    'xmldb:get-group' => 'sm:get-group*',
    'xmldb:get-owner' => 'sm:get-permissions',
    'xmldb:get-user-groups' => 'sm:get-user-groups',
    'xmldb:get-user-home' => 'obsolete -- none available',
    'xmldb:get-user-primary-group' => 'sm:get-user-primary-group',
    'xmldb:get-users' => 'sm:list-users',
    'xmldb:group-exists' => 'sm:group-exists',
    'xmldb:is-admin-user' => 'sm:is-dba',
    'xmldb:is-authenticated' => 'sm:is-authenticated or sm:is-externally-authenticated',
    'xmldb:get-permissions' => 'sm:get-permissions',
    'xmldb:permissions-to-string' => 'sm:octal-to-mode',
    'xmldb:string-to-permissions' => 'sm:mode-to-octal',
    'xmldb:remove-user-from-group' => 'sm:remove-group-member',
    'xmldb:set-collection-permissions' => 'sm:chmod sm:chown sm:chgrp',
    'xmldb:set-resource-permissions' => 'sm:chmod sm:chown sm:chgrp',
    'xdb:add-user-to-group' => 'sm:add-group-member',
    'xdb:change-user' => 'more specific sm function',
    'xdb:chmod-collection' => 'sm:chmod',
    'xdb:chmod-resource' => 'sm:chmod',
    'xdb:copy' => 'xmldb:copy-collection or xmldb:copy-resource (no replacement in 4.x.x!)',
    'xdb:create-group' => 'sm:create-group',
    'xdb:create-user' => 'sm:create-account',
    'xdb:delete-user' => 'sm:remove-account',
    'xdb:document' => 'fn:doc',
    'xdb:exists-user' => 'sm:user-exists',
    'xdb:get-current-user' => 'sm:id',
    'xdb:get-current-user-attribute' => 'sm:get-account-metadata',
    'xdb:get-current-user-attribute-names' => 'sm:get-account-metadata-keys',
    'xdb:get-group' => 'sm:get-group*',
    'xdb:get-owner' => 'sm:get-permissions',
    'xdb:get-user-groups' => 'sm:get-user-groups',
    'xdb:get-user-home' => 'obsolete -- none available',
    'xdb:get-user-primary-group' => 'sm:get-user-primary-group',
    'xdb:get-users' => 'sm:list-users',
    'xdb:group-exists' => 'sm:group-exists',
    'xdb:is-admin-user' => 'sm:is-dba',
    'xdb:is-authenticated' => 'sm:is-authenticated or sm:is-externally-authenticated',
    'xdb:get-permissions' => 'sm:get-permissions',
    'xdb:permissions-to-string' => 'sm:octal-to-mode',
    'xdb:string-to-permissions' => 'sm:mode-to-octal',
    'xdb:remove-user-from-group' => 'sm:remove-group-member',
    'xdb:set-collection-permissions' => 'sm:chmod sm:chown sm:chgrp',
    'xdb:set-resource-permissions' => 'sm:chmod sm:chown sm:chgrp',
    # following are built-ins that may not be caught by the module check below
    'httpclient:get' => 'EXPath HTTP Client',
    'httpclient:post' => 'EXPath HTTP Client',
    'httpclient:put' => 'EXPath HTTP Client',
    'httpclient:delete' => 'EXPath HTTP Client',
);

my %removed_modules = (
    'context' => 'http://exist-db.org/xquery/context|... sorry, obsolete -- no replacement available',
    'datetime' => 'http://exist-db.org/xquery/datetime|XQuery 3.1, FunctX, or other implementations',
    'ftp' => 'http://exist-db.org/xquery/ftpclient|EXPath File Transfer Client',
    'httpclient' => 'http://exist-db.org/xquery/httpclient|EXPath HTTP Client',
    'math-ext' => 'http://exist-db.org/xquery/math|XQuery 3.1 math module',
    'memcached' => 'http://exist-db.org/xquery/memcached|... sorry, obsolete -- no replacement available',
    'svn' => 'http://exist-db.org/xquery/versioning/svn|https://github.com/shabanovd/eXist-svn',
    'xmpp' => 'http://exist-db.org/xquery/xmpp|... sorry, obsolete -- no replacement available',
);

my %func_lines;
my %module_lines;

my @files;

sub match_files {
    push @files, $File::Find::name if ($_ =~ m/\.xq(l|m)?$/);
}

my $dir = $ARGV[0] || File::Spec->curdir();
find(\&match_files, $dir);

sub scan_file {
    my $file = shift;
    open my $fh, '<', $file or die "Couldn't open $file: $!";
    my $line_num = 0;
    while (my $line = <$fh>) {
        $line_num++;
        for my $func (sort keys %removed_funcs) {
            # Avoid "declare variable $m as  map()", which is not a function call.
            next if $line =~ m/\bas\s+${func}\(/;

            if ($line =~ m/
                (?<![\$\-])\b            # word boundary but negative lookbehind preventing $ or -
                ${func}\s*               # function name followed by optional whitespace
                \(\s*                    # left paren followed by optional whitespace
                (?![\+\?\\*]             # negative lookahead disallowing quantifiers
                |xs:integer              # and data types, which indicate declarations
                |xs:string               # rather than functions (mostly for 'map')
                |function
                |xs:anyURI
                |xs:boolean
                |xs:byte
                |xs:date
                |xs:dateTime
                |xs:decimal
                |xs:dayTimeDuration
                |xs:double
                |xs:duration
                |xs:float
                |xs:gDay
                |xs:gMonthDay
                |xs:gYear
                |xs:gYearMonth
                |xs:long
                |xs:Name
                |xs:QName
                |xs:short
                |xs:time
                |xs:yearMonthDuration
                ) # end of negative lookahead
                /x) {
                    push @{$func_lines{$func}}, "$file:$line_num $line";
            }
        }

        for my $mod (sort keys %removed_modules) {
            my ($ns, $replacement) = split /\|/, $removed_modules{$mod};
            my $namespace = qr{$ns};
            if ($line =~ m/import module namespace\s+.*$namespace/) {
                push @{$module_lines{$mod}}, "$file:$line_num $line";
            }
        }
    }
    close $fh;
}

while (my $file = shift @files) {
    scan_file($file);
}

for my $func (sort keys %func_lines) {
    print "\n>>>  Replace the following instances of the function $func with $removed_funcs{$func}.\n\n";
    while (my $line = shift @{$func_lines{$func}}) { print $line; }
}

for my $mod (sort keys %module_lines) {
    my ($ns, $replacement) = split /\|/, $removed_modules{$mod};
    print "\n>>>  Replace the following instances of the module $mod with $replacement.\n\n";
    while (my $line = shift @{$module_lines{$mod}}) { print $line; }
}

print "\n";
exit;
