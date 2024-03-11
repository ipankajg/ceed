SRCDIR=src
OUTDIR=out
OBJDIR=$(OUTDIR)/obj
CC=gcc
CFLAGS=-I$(SRCDIR) -I$(OUTDIR) -w -std=c99
DEPS = ceed.h ceed.tab.h
OBJ  = lex.yy.o ceed.tab.o ceedcmpl.o ceedelf.o ceedpe.o ceedrtl.o main.o ceedcmpl64.o ceedpe64.o 
OBJS = $(addprefix $(OBJDIR)/,$(OBJ))

all: $(OUTDIR) $(OUTDIR)/ceed
	
$(OUTDIR):
	mkdir $(OUTDIR)
	mkdir $(OBJDIR)
	
$(OUTDIR)/ceed: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OUTDIR)/lex.yy.c $(OUTDIR)/ceed.tab.c $(OUTDIR)/ceed.tab.h: $(SRCDIR)/ceed.l $(SRCDIR)/ceed.y
	bison -d $(SRCDIR)/ceed.y -o $(OUTDIR)/ceed.tab.c
	flex -o $(OUTDIR)/lex.yy.c $(SRCDIR)/ceed.l 

$(OBJDIR)/%.o: $(OUTDIR)/%.c
	$(CC)  -c $(CFLAGS) -o $@ $<
	
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC)  -c $(CFLAGS) -o $@ $<


clean:
	@rm -rf $(OUTDIR)

