#!/usr/bin/perl
$linecount=0;$matcher="GRANTED";
while(<>){
if( m/$matcher/ ){
 $linecount++; chomp($_);
 split(/:/,$_);
 print " 1: "; print(@_[1]); print " 2: "; print(@_[2]); print " 3: ";
 print(@_[3]); print " 4: ";  print(@_[4]); print " 5: ";  ; print(@_[5]);
 print " 6: " ; print(@_[6]); print "\n";
 print "\n";
 print;
 print "\n";
 }
}
print " total count matching $matcher was : " . $linecount . "\n";


__END__
2009.04.14 12:16:46 SchedulerGroup: gsu|NURS 7550 - CRANWELL-BRUCE#C.5BA953F7F8E85C16979CB12721722D: Access GRANTED - Nadia Fadli/76.105.103.51:50144,direct,jinx
2009.04.14 12:16:52 SchedulerGroup: elluminate_voffice|CHRISTINE POLLARD#M.2F0FD26F6D192E53B11145A0EE707F: Access GRANTED - Roger/12.169.251.20:14172,direct,ssljinx
2009.04.14 12:16:58 SchedulerGroup: elluminate_vclass|DSBF E.V#D.949FDFFD17C53273B5BA1B06FB234B: Access GRANTED - Bernd Schweizer/91.19.251.133:14326,direct,ssljinx
2009.04.14 12:16:59 SchedulerGroup: cmvroom070601|TERI.SCHMIDT@JETBLUE.COM_CQGGFMWXH7VGAHWC#D.6E1B6B2FEC7A936304B6702290D051: Access GRANTED - Teri Schmidt 1/97.102.110.6:50270,direct,ssljinx
2009.04.14 12:17:04 SchedulerGroup: k12|HISTORY#M.2158CBD278DDEEB2DC781E59F7A0BE: Access GRANTED - Talia6759/71.79.39.38:4649,direct,jinx
2009.04.14 12:17:15 SchedulerGroup: paho|THR EM - POLÍTICAS DE MEDICAMENTOS#M.FAE3E84FA9E70B318ECBE54F307732: Access GRANTED - Jose 1/200.6.193.89:15297,direct,ssljinx
2009.04.14 12:17:25 SchedulerGroup: ibml04|NETWORKING - AMERICAS 1#D.27CC32A5B4766357B3652102355292: Access GRANTED - Alex Zhong/129.33.49.251:43861,direct,jinx
2009.04.14 12:17:27 SchedulerGroup: cmvroom090220|PLUMERIACA@GMAIL.COM_QZW4AZZ9030SZSQR#D.E7099FF1A8316075EFF34D2ED81A36: Access GRANTED - Teal Speece/70.212.148.137:2945,http(full),ssljinx
2009.04.14 12:17:34 SchedulerGroup: k12|HOU AREA STUDY HALL A (GRADES 3, 5, 7)#M.ACD3B0953ABE3472DA9BA642790D60: Access GRANTED - CosmeCAS_medina/71.30.165.77:60760,direct,jinx
2009.04.14 12:17:35 SchedulerGroup: cmvroom070601|JAVIER@COLOMUSA.COM_4IF9M1NVI3LCLVTH#D.7134000CF0851AF34E9FB58720472C: Access GRANTED - Sam & Dave/98.221.160.144:3343,direct,ssljinx
2009.04.14 12:17:39 SchedulerGroup: k12|LAURA BLAUCH'S ELLUMINATE CLASSROOM#M.4457CBC3EC8EAC22BAB1FB2389E94C: Access GRANTED - Sarah Lowry/24.239.243.173:2610,direct,jinx
2009.04.14 12:17:42 SchedulerGroup: elluminate_voffice|IDC TECHNOLOGIES 3#M.97521BE1D93D7A148473F5725DC7E0: Access GRANTED - Sharne Pretorius 1/62.49.76.250:31451,direct,ssljinx
2009.04.14 12:17:44 SchedulerGroup: k12|HATROCK LANGUAGE B#M.7C05EF472220864F350758235F935D: Access GRANTED - Amber Hatrock/205.201.114.97:1801,direct,jinx
2009.04.14 12:17:58 SchedulerGroup: cmvroom080116|GJAMES@KUMC.EDU_7IOO2LJH5PLATBVB#D.6B2E7CF71C46A73CDBA1CE654A2AB2: Access GRANTED - Grant James/169.147.3.25:31058,direct,ssljinx
2009.04.14 12:18:01 SchedulerGroup: novell|EUC GERMAN PARTNER ENABLEMENT WEBCAST#M.0F68997D8E89D9DC66B25082C58BD1: Access GRANTED - harald.gemmer@carpediem.de/87.139.76.134:26336,direct,ssljinx
2009.04.14 12:18:09 SchedulerGroup: k12|HISTORY#M.2158CBD278DDEEB2DC781E59F7A0BE: Access GRANTED - Nickolas207950/98.28.64.168:1698,direct,jinx
2009.04.14 12:18:40 SchedulerGroup: k12|JILL SWATTON'S AGORA CLASSROOM#M.36A3BE9976383B245E7A9CE0D15663: Access GRANTED - Lydia G/Swatton/207.255.60.100:2185,direct,jinx
2009.04.14 12:18:41 SchedulerGroup: cmvroom070601|JOAKIM.WESTLUND@PULSEN.SE_4FHDGTRAZXQGFREB#D.C3AC8CC392ACA5C4891F406C610540: Access GRANTED - Joakim Westlund/90.227.130.95:64319,direct,ssljinx
2009.04.14 12:19:05 SchedulerGroup: ei_opschk|OPSSVRCHK EL12#M.95C29DDBD81F61C0D532D6FE4854AB: Access GRANTED - Tester/208.98.242.129:16597,direct,jinx
2009.04.14 12:19:07 SchedulerGroup: lt|ACRL-ELEARNING-LEARNINGTIMES-V9#M.3A662879E24CA11917ADF4BBED1CBC: Access GRANTED - Margaret Devereaux 1/150.155.1.236:1832,direct,jinx
2009.04.14 12:19:17 SchedulerGroup: elluminate_vclass|TWU ONLINE#D.502CD25A44AAB8641352936618FCFA: Access GRANTED - Stephany Compton/70.129.13.10:47189,direct,jinx
2009.04.14 12:19:27 SchedulerGroup: tpr|PRINCETON REVIEW ONLINE - REESA'S CLASSROOM#M.04B89FF9BDF67D4A91A45B843128CB: Access GRANTED - William LeDoux/74.193.210.241:61622,direct,jinx
2009.04.14 12:19:30 SchedulerGroup: cmvroom090220|63@MATHS-DOCTOR.COM_R6ULE6H0GPKQOJIT#D.5560DDFF73B0282E5B4E1417ABA0C8: Access GRANTED - Room 63/81.153.55.101:49909,direct,ssljinx
2009.04.14 12:19:45 SchedulerGroup: cmvroom081208|BLACKLOVE05@ATT.NET_RGKZYCDCEJE61WR3#D.BEC23BF28B293F7D27CB3D8B0ECACD: Access GRANTED - Mandy Gomez/75.47.133.209:56048,direct,ssljinx
2009.04.14 12:19:55 SchedulerGroup: sdbr|NSU - KAMI FISCHBACH#M.D34191D28330ABE9F0B9360398D11D: Access GRANTED - Brian B/206.176.116.211:53617,direct,ssljinx
2009.04.14 12:19:55 SchedulerGroup: k12|HOU AREA STUDY HALL A (GRADES 3, 5, 7)#M.ACD3B0953ABE3472DA9BA642790D60: Access GRANTED - .:Cedric.Shy_Lipscomb:./98.198.193.40:2595,direct,jinx
2009.04.14 12:19:59 SchedulerGroup: k12|HOU AREA STUDY HALL A (GRADES 3, 5, 7)#M.ACD3B0953ABE3472DA9BA642790D60: Access GRANTED - Alyssa/98.197.218.18:52741,direct,jinx
2009.04.14 12:20:21 SchedulerGroup: elluminate_voffice|OPENENGLISH.COM#M.FC97773980BC207E9B6F43CC63B730: Access GRANTED - Wilmer Sarmiento/200.109.37.4:4084,direct,ssljinx
2009.04.14 12:20:29 SchedulerGroup: k12|HOU AREA STUDY HALL A (GRADES 3, 5, 7)#M.ACD3B0953ABE3472DA9BA642790D60: Access GRANTED - austindav_ramirez/70.192.61.186:50609,direct,jinx
2009.04.14 12:20:39 SchedulerGroup: k12|LAURA BLAUCH'S ELLUMINATE CLASSROOM#M.4457CBC3EC8EAC22BAB1FB2389E94C: Access GRANTED - armando/24.144.165.223:2118,direct,jinx