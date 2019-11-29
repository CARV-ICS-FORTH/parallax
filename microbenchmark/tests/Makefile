mttest1: mttest1.cc testhdr.h
	gcc -g -I.. mttest1.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest1 -lrt -pthread -lm -lcheck
	
mttest2: mttest2.cc testhdr.h
	gcc -g -I.. mttest2.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest2 -lrt -pthread -lm -lcheck
	
mttest3: mttest3.cc testhdr.h
	gcc -g -I.. mttest3.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest3 -lrt -pthread -lm -lcheck
	
mttest4: mttest4.cc testhdr.h
	gcc -g -I.. mttest4.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest4 -lrt -pthread -lm -lcheck
	
mttest5: mttest5.cc testhdr.h
	gcc -g -I.. mttest5.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest5 -lrt -pthread -lm -lcheck
	
mttest6: mttest6.cc testhdr.h
	gcc -g -I.. mttest6.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest6 -lrt -pthread -lm -lcheck
	
mttest7: mttest7.cc testhdr.h
	gcc -g -I.. mttest7.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest7 -lrt -pthread -lm -lcheck
	
mttest8: mttest8.cc testhdr.h
	gcc -g -I.. mttest8.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest8 -lrt -pthread -lm -lcheck
	
mttest9: mttest9.cc testhdr.h
	gcc -g -I.. mttest9.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest9 -lrt -pthread -lm -lcheck
	
mttest10: mttest10.cc testhdr.h
	gcc -g -I.. mttest10.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest10 -lrt -pthread -lm -lcheck
	
mttest11: mttest11.cc testhdr.h
	gcc -g -I.. mttest11.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest11 -lrt -pthread -lm -lcheck
	
test1: test1.cc testhdr.h
	gcc -g -I.. test1.cc /home/christopher/HEutropia/btree/libEutropia.a -o test1 -lrt -pthread -lm -lcheck
	
test2: test2.cc testhdr.h
	gcc -g -I.. test2.cc /home/christopher/HEutropia/btree/libEutropia.a -o test2 -lrt -pthread -lm -lcheck
	
test3: test3.cc testhdr.h
	gcc -g -I.. test3.cc /home/christopher/HEutropia/btree/libEutropia.a -o test3 -lrt -pthread -lm -lcheck
	
test4: test4.cc testhdr.h
	gcc -g -I.. test4.cc /home/christopher/HEutropia/btree/libEutropia.a -o test4 -lrt -pthread -lm -lcheck
	
test5: test5.cc testhdr.h
	gcc -g -I.. test5.cc /home/christopher/HEutropia/btree/libEutropia.a -o test5 -lrt -pthread -lm -lcheck
	
test6: test6.cc testhdr.h
	gcc -g -I.. test6.cc /home/christopher/HEutropia/btree/libEutropia.a -o test6 -lrt -pthread -lm -lcheck
	
test7: test7.cc testhdr.h
	gcc -g -I.. test7.cc /home/christopher/HEutropia/btree/libEutropia.a -o test7 -lrt -pthread -lm -lcheck
	
test8: test8.cc testhdr.h
	gcc -g -I.. test8.cc /home/christopher/HEutropia/btree/libEutropia.a -o test8 -lrt -pthread -lm -lcheck	
	
mttest1.cc: mttest1.check
	checkmk mttest1.check > mttest1.cc
	
mttest2.cc: mttest2.check
	checkmk mttest2.check > mttest2.cc
	
mttest3.cc: mttest3.check
	checkmk mttest3.check > mttest3.cc
	
mttest4.cc: mttest4.check
	checkmk mttest4.check > mttest4.cc
	
mttest5.cc: mttest5.check
	checkmk mttest5.check > mttest5.cc
	
mttest6.cc: mttest6.check
	checkmk mttest6.check > mttest6.cc
	
mttest7.cc: mttest7.check
	checkmk mttest7.check > mttest7.cc
	
mttest8.cc: mttest8.check
	checkmk mttest8.check > mttest8.cc
	
mttest9.cc: mttest9.check
	checkmk mttest9.check > mttest9.cc
	
mttest10.cc: mttest10.check
	checkmk mttest10.check > mttest10.cc
	
mttest11.cc: mttest11.check
	checkmk mttest11.check > mttest11.cc
	
test1.cc: test1.check
	checkmk test1.check > test1.cc
	
test2.cc: test2.check
	checkmk test2.check > test2.cc
	
test3.cc: test3.check
	checkmk test3.check > test3.cc
	
test4.cc: test4.check
	checkmk test4.check > test4.cc
	
test5.cc: test5.check
	checkmk test5.check > test5.cc
	
test6.cc: test6.check
	checkmk test6.check > test6.cc
	
test7.cc: test7.check
	checkmk test7.check > test7.cc
	
test8.cc: test8.check
	checkmk test8.check > test8.cc	
	
mtrun1:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest1
	
mtrun2:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest2
	
mtrun3:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest3
	
mtrun4:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest4
	
mtrun5:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest5
	
mtrun6:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest6
	
mtrun7:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest7
	
mtrun8:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest8
	
mtrun9:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest9
	
mtrun10:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest10
	
mtrun11:
	CK_DEFAULT_TIMEOUT=100000000 ./mttest11
	
run1:
	CK_DEFAULT_TIMEOUT=100000000 ./test1
	
run2:
	CK_DEFAULT_TIMEOUT=100000000 ./test2
	
run3:
	CK_DEFAULT_TIMEOUT=100000000 ./test3
	
run4:
	CK_DEFAULT_TIMEOUT=100000000 ./test4
	
run5:
	CK_DEFAULT_TIMEOUT=100000000 ./test5
	
run6:
	CK_DEFAULT_TIMEOUT=100000000 ./test6
	
run7:
	CK_DEFAULT_TIMEOUT=100000000 ./test7
	
run8:
	CK_DEFAULT_TIMEOUT=100000000 ./test8
	
run_all:
	CK_DEFAULT_TIMEOUT=100000000 ./test1
	@echo "\033[0;32mSimple test 1 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./test2
	@echo "\033[0;32mSimple test 2 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./test3
	@echo "\033[0;32mSimple test 3 finished.\033[0m\n"
	
#	CK_DEFAULT_TIMEOUT=100000000 ./test4
#	@echo "\033[0;32mSimple test 4 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./test5
	@echo "\033[0;32mSimple test 5 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./test6
	@echo "\033[0;32mSimple test 6 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./test7
	@echo "\033[0;32mSimple test 7 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./test8
	@echo "\033[0;32mSimple test 8 finished.\033[0m\n"
	@echo "\033[0;32mALL SIMPLE TESTS DONE.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest1
	@echo "\033[0;32mMulti-threaded test 1 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest2
	@echo "\033[0;32mMulti-threaded test 2 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest3
	@echo "\033[0;32mMulti-threaded test 3 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest4
	@echo "\033[0;32mMulti-threaded test 4 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest5
	@echo "\033[0;32mMulti-threaded test 5 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest6
	@echo "\033[0;32mMulti-threaded test 6 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest7
	@echo "\033[0;32mMulti-threaded test 7 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest8
	@echo "\033[0;32mMulti-threaded test 8 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest9
	@echo "\033[0;32mMulti-threaded test 9 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest10
	@echo "\033[0;32mMulti-threaded test 10 finished.\033[0m\n"
	
	CK_DEFAULT_TIMEOUT=100000000 ./mttest11
	@echo "\033[0;32mMulti-threaded test 11 finished.\033[0m\n"
	@echo "\033[0;32mALL MULTI-THREADED TESTS DONE.\033[0m\n"
	@echo "ALL TESTS COMPLETED\n"
	
clean:
	rm -f *.cc
	rm -f mttest1
	rm -f mttest2
	rm -f mttest3
	rm -f mttest4
	rm -f mttest5
	rm -f mttest6
	rm -f mttest7
	rm -f mttest8
	rm -f mttest9
	rm -f mttest10
	rm -f mttest11
	
	rm -f test1
	rm -f test2
	rm -f test3
	rm -f test4
	rm -f test5
	rm -f test6
	rm -f test7
	rm -f test8
	
all: testhdr.h
	checkmk mttest1.check > mttest1.cc
	checkmk mttest2.check > mttest2.cc
	checkmk mttest3.check > mttest3.cc
	checkmk mttest4.check > mttest4.cc
	checkmk mttest5.check > mttest5.cc
	checkmk mttest6.check > mttest6.cc
	checkmk mttest7.check > mttest7.cc
	checkmk mttest8.check > mttest8.cc
	checkmk mttest9.check > mttest9.cc
	checkmk mttest10.check > mttest10.cc
	checkmk mttest11.check > mttest11.cc
	
	checkmk test1.check > test1.cc
	checkmk test2.check > test2.cc
	checkmk test3.check > test3.cc
	checkmk test4.check > test4.cc
	checkmk test5.check > test5.cc
	checkmk test6.check > test6.cc
	checkmk test7.check > test7.cc
	checkmk test8.check > test8.cc
	
	gcc -g -I.. mttest1.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest1 -lrt -pthread -lm -lcheck
	gcc -g -I.. mttest2.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest2 -lrt -pthread -lm -lcheck
	gcc -g -I.. mttest3.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest3 -lrt -pthread -lm -lcheck
	gcc -g -I.. mttest4.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest4 -lrt -pthread -lm -lcheck
	gcc -g -I.. mttest5.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest5 -lrt -pthread -lm -lcheck
	gcc -g -I.. mttest6.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest6 -lrt -pthread -lm -lcheck
	gcc -g -I.. mttest7.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest7 -lrt -pthread -lm -lcheck
	gcc -g -I.. mttest8.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest8 -lrt -pthread -lm -lcheck
	gcc -g -I.. mttest9.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest9 -lrt -pthread -lm -lcheck
	gcc -g -I.. mttest10.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest10 -lrt -pthread -lm -lcheck
	gcc -g -I.. mttest11.cc /home/christopher/HEutropia/btree/libEutropia.a -o mttest11 -lrt -pthread -lm -lcheck
	
	gcc -g -I.. test1.cc /home/christopher/HEutropia/btree/libEutropia.a -o test1 -lrt -pthread -lm -lcheck
	gcc -g -I.. test2.cc /home/christopher/HEutropia/btree/libEutropia.a -o test2 -lrt -pthread -lm -lcheck
	gcc -g -I.. test3.cc /home/christopher/HEutropia/btree/libEutropia.a -o test3 -lrt -pthread -lm -lcheck
	gcc -g -I.. test4.cc /home/christopher/HEutropia/btree/libEutropia.a -o test4 -lrt -pthread -lm -lcheck
	gcc -g -I.. test5.cc /home/christopher/HEutropia/btree/libEutropia.a -o test5 -lrt -pthread -lm -lcheck
	gcc -g -I.. test6.cc /home/christopher/HEutropia/btree/libEutropia.a -o test6 -lrt -pthread -lm -lcheck
	gcc -g -I.. test7.cc /home/christopher/HEutropia/btree/libEutropia.a -o test7 -lrt -pthread -lm -lcheck
	gcc -g -I.. test8.cc /home/christopher/HEutropia/btree/libEutropia.a -o test8 -lrt -pthread -lm -lcheck
