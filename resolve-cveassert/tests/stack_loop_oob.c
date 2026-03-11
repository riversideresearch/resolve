void vuln(char *buf) {
   for (int i = 0; i < 17; ++i) {
      buf[i] = 0x69;
   }
}

int main() {
   char tmp[8] = {0, 1, 2, 3, 4, 5, 6, 7};
   vuln(tmp);
   return 0;
}