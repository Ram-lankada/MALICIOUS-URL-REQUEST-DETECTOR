from django.http import HttpResponse
from django.shortcuts import render 
import pickle
import joblib 
import numpy as np
import pandas as pd 
from django.contrib import messages
from django.conf.urls.static import static
from django.utils.safestring import mark_safe
from django.template import Library


count = 0 

def url(request) :
    if request.method == 'POST' :         
        if request.POST["urlname"] : 
                
                global count 
                # LOADING MODELS 
                
                lr_model = pickle.load(open("lr_model.pkl", "rb"))
                mnb_model = pickle.load(open("mnb_model.pkl", "rb")) 
                # xgb_model = pickle.load(open("xgb_pipeline.pkl", "rb")) 
                # sgd_model = pickle.load(open("sgd_pipeline.pkl", "rb"))

                
                # NOT TRAINED MODELS 
                xgb_classifier = pickle.load(open("xgb_classifier.pkl", "rb")) 
                ada_classifier = pickle.load(open("ada_classifier.pkl", "rb")) 
                sgd_classifier = pickle.load(open("sgd_classifier.pkl", "rb")) 
                lr_classifier = pickle.load(open("lr_classifier.pkl", "rb")) 
                rf_classifier = pickle.load(open("rf_classifier.pkl", "rb")) 
                svm_classifier = pickle.load(open("svm_classifier.pkl", "rb")) 
                dt_classifier = pickle.load(open("dt_classifier.pkl", "rb")) 
                mnb_classifier = pickle.load(open("mnb_classifier.pkl", "rb")) 

                # PAYLOAD FETCHING 
                
                payload = [] 
                payload.append(request.POST["urlname"]) 
                print( payload ) 
                
                # FUNCITONS FOR PREDICTING 
                
                # Random forest classifier 
                '''
                def injection_test(input):
                    variables = input.split('&')
                    values = [ variable.split('=')[1] for variable in variables]
                    print(values)
                    return 'MALICIOUS' if rf_classifier.predict(values).sum() > 0 else 'NOT_MALICIOUS'
                '''
                
                # XGB Classifier 
                sql_keywords = pd.read_csv('https://trello-attachments.s3.amazonaws.com/5ed2d4107c349c221194b608/5ed2d453f0e5a45bcd8cf16c/435e639346787ce2b495a16e9f690ef5/SQLKeywords.txt', index_col=False)
                js_keywords = pd.read_csv("https://trello-attachments.s3.amazonaws.com/5ed2d4107c349c221194b608/5ed2d453f0e5a45bcd8cf16c/dedc7eb9846a30c252cd950a0e2153d9/JavascriptKeywords.txt",index_col=False)
                
                def ret_features(payload) : 
                    features = {} 
                    payload = str(payload)
                    features['length'] = len(payload)
                    features['non-printable'] = len([1 for letter in payload if letter not in str('printable')])
                    features['punctuation'] = len([1 for letter in payload if letter in str('punctuation')])
                    features['min-byte'] = min(bytearray(payload,'utf-8'))
                    features['max-byte'] = max(bytearray(payload,'utf-8'))
                    features['mean-byte'] = np.mean(bytearray(payload,'utf-8'))
                    features['std-byte'] = np.std(bytearray(payload,'utf-8'))
                    features['distinct-byte'] = len(set(bytearray(payload,'utf-8')))
                    features['sql-keywords'] = len([1 for keyword in sql_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
                    features['js-keywords'] = len([1 for keyword in js_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
                    #payload_df = pd.DataFrame(data=features,index=[0],columns=independent_variables)
                    
                    # Have not returned the features 
                    return(features) 
                    
                
                def predict( payload , select ) : 
                    features = ret_features(payload) 
                    print("features:",features) 
                    
                    # Here the dataframe is two attribute indexed data structure it has to be indexed individually.
                    match select : 
                        
                        case 0 :  # MANUAL TUNING 
                            
                            payload_df = pd.DataFrame(features,index=[0])
                            
                            print("XGB")
                            print("\n", payload_df , "\n") 
                            result = xgb_classifier.predict(payload_df)
                            
                            ThresOpt = 0.448599994182586
                            opt = xgb_classifier.predict_proba(payload_df)
                            opt = opt[:,1]
                            
                            if( opt > ThresOpt ) :
                                global count 
                                count = count + 1 
                                opt_result = "bad"
                            else :
                                opt_result = "good" 
                            
                            # prob = xgb_classifier.predict_proba(payload_df)
                            # prob = prob[:,1]
                            # print( prob )
                            
                        case 1 : # HYPERPLANE
                            
                            print("ada_classifier")
                            payload_df = pd.DataFrame(features,index=[1])
                            print("\n", payload_df , "\n") 
                            result = ada_classifier.predict(payload_df)
                            
                            ThresOpt = 0.4839
                            opt = ada_classifier.decision_function(payload_df)

                            if( opt < ThresOpt ) :
                                opt_result = "good"
                            else : 
                                count = count + 1 
                                opt_result = "bad" 
                                
                            # prob = ada_classifier.predict_proba(payload_df)
                            # prob = prob[:,1]
                            # print( prob )                        
                            
                        case 2 : # NO TUNING  
                            
                            print("sgd_classifier")
                            payload_df = pd.DataFrame(features,index=[2])
                            print("\n", payload_df , "\n") 
                            result = sgd_classifier.predict(payload_df)
                            
                            if result == [1] : 
                                count = count + 1 
                                return("bad")
                            elif(result == [0]):
                                return("good") 
                    
                            # print( sgd_classifier.predict_proba(payload_df) )
                            
                        case 3 : # HYPERPLANE
                            
                            print("lr_classifier")
                            payload_df = pd.DataFrame(features,index=[3])
                            print("\n", payload_df , "\n") 
                            result = lr_classifier.predict(payload_df)
                            
                            ThresOpt = 0.175
                            
                            opt = lr_classifier.decision_function(payload_df)

                            if( opt < ThresOpt ) :
                                opt_result = "good"
                            else :
                                count = count + 1 
                                opt_result = "bad" 
                                
                            # prob = lr_classifier.predict_proba(payload_df)
                            # prob = prob[:,1]
                            # print( prob )
                            
                        case 4 : # MANUAL TUNING 
                            
                            print("rf_classifier")
                            payload_df = pd.DataFrame(features,index=[4]) 
                            print("\n", payload_df , "\n")                   
                            result = rf_classifier.predict(payload_df)

                            ThresOpt = 0.59
                            
                            opt = lr_classifier.predict_proba(payload_df)
                            opt = opt[:,1]
                            
                            if( opt > ThresOpt ) :
                                count = count + 1 
                                opt_result = "bad"
                            else :
                                opt_result = "good" 
                                
                            # prob = rf_classifier.predict_proba(payload_df)
                            # prob = prob[:,1]
                            # print( prob )
                                                        
                        case 5 : # HYPERPLANE
                            
                            print("svm_classifier")
                            payload_df = pd.DataFrame(features,index=[5])
                            print("\n", payload_df , "\n") 
                            result = svm_classifier.predict(payload_df)
                            
                            ThresOpt = 0.1493
                            
                            opt = svm_classifier.decision_function(payload_df)

                            if( opt < ThresOpt ) :
                                opt_result = "good"
                            else :
                                count = count + 1 
                                opt_result = "bad" 
                                
                            # print( svm_classifier.predict_proba(payload_df) )
                            
                        case 6 : # NO TUNING 
                            
                            print("dt_classifier")
                            payload_df = pd.DataFrame(features,index=[6])
                            print("\n", payload_df , "\n") 
                            result = dt_classifier.predict(payload_df)
                            
                            if result == [1] : 
                                count = count + 1 
                                return("bad")
                            elif(result == [0]):
                                return("good")
                                
                            prob = dt_classifier.predict_proba(payload_df)
                            prob = prob[:,1]
                            print( prob )                            
                            
                        case 7 : # MANUAL TUNING 
                            
                            print("mnb_classifier")
                            payload_df = pd.DataFrame(features,index=[7])
                            print("\n", payload_df , "\n") 
                            result = mnb_classifier.predict(payload_df)
                            
                            ThresOpt = 0.5309
                            
                            opt = lr_classifier.predict_proba(payload_df)
                            opt = opt[:,1]
                            
                            if( opt > ThresOpt ) :
                                count = count + 1 
                                opt_result = "bad"
                            else :
                                opt_result = "good" 
                                
                            # prob = mnb_classifier.predict_proba(payload_df)
                            # prob = prob[:,1]
                            # print( prob )

                    print( result ) 
                    print("----------------------------------")
                    
                    if result == [1] : 
                        count = count + 1 
                        return(["bad",opt_result])
                    elif(result == [0]):
                        return(["good",opt_result]) 
                    
                    
                # PREDICTION 
                
                lr_p = lr_model.predict(payload) 
                if( lr_p == "bad") : 
                    count = count + 1 
                
                print("----------------LR_MODEL-----------------")
                prob = lr_model.predict_proba(payload)
                prob = prob[:,1]
                print( prob )  
                print(lr_p)
                
                mnb_p = mnb_model.predict(payload) 
                if( lr_p == "bad") : 
                    count = count + 1 
                    
                print("\n----------------MNB_MODEL-----------------")
                prob = mnb_model.predict_proba(payload)
                prob = prob[:,1]
                print( prob ) 
                print(mnb_p)  
                
                # xgb_p = xgb_model.predict(payload) 
                # if( xgb_p == 1 ) :
                #     xgb_p = "good"
                # else : 
                #     xgb_p = "bad" 
                    
                    
                # sgd_p = sgd_model.predict(payload) 
                # if( sgd_p == 1 ) :
                #     sgd_p = "good"
                # else : 
                #     sgd_p = "bad"
                
                # xgb = xgb_classifier.predict(payload)  
                # rf  = injection_test(payload) 
                # svc = svc_model.predict(payload)
                
                # NT MODEL PREDICTIONS 
                
                # HYPER PLANE TUNING PREDICTION 
                xgb = predict(payload , 0 ) 
                xgb_n = xgb[0]
                xgb_hyp = xgb[1]
                
                ada = predict(payload , 1 ) 
                ada_n = ada[0]
                ada_hyp = ada[1]
                
                lr = predict(payload , 3 ) 
                lr_n = lr[0]
                lr_hyp = lr[1]
                
                svm = predict(payload , 5 ) 
                svm_n = svm[0]
                svm_hyp = svm[1]
                
                # PROBABILITY TUNING PREDICTION 
                rf = predict(payload , 4 ) 
                rf_n = rf[0]
                rf_opt = rf[1]
                
                mnb = predict(payload , 7 ) 
                mnb_n = mnb[0]
                mnb_opt = mnb[1]
                
                # NO TUNING PREDICTION 
                sgd_FE = predict(payload , 2 )
                dt_FE = predict(payload , 6 ) 
                
                print( "ensemble count:",count ) 
                if( count >= 8 ) : 
                    ensemble = "bad"
                else : 
                    ensemble = "good"

                
                # xgb_NT = NT_predict(payload , 0 ) 
                # ada_NT = NT_predict(payload , 1 ) 
                # sgd_NT = NT_predict(payload , 2 ) 
                # lr_NT = NT_predict(payload , 3 ) 
                # rf_NT = NT_predict(payload , 4 ) 
                # svm_NT = NT_predict(payload , 5 ) 
                # dt_NT = NT_predict(payload , 6 ) 
                # mnb_NT = NT_predict(payload , 7 ) 

                context={
                    
                    # PIPELINES 
                    "lr_p":lr_p , 
                    "mnb_p": mnb_p,
                    # "xgb_p" : xgb_p, 
                    # "sgd_p" : sgd_p, 
                    
                    # HYP TUNING 
                    "xgb_n" : xgb_n, 
                    "xgb_hyp" : xgb_hyp, 
                    "ada_n" : ada_n, 
                    "ada_hyp" : ada_hyp, 
                    "lr_n" : lr_n, 
                    "lr_hyp" : lr_hyp, 
                    "svm_n" : svm_n, 
                    "svm_hyp" : svm_hyp, 
                    
                    # OPT TUNING 
                    "rf_n" : rf_n,  
                    "rf_opt" : rf_opt,  
                    "mnb_n" : mnb_n,
                    "mnb_opt" : mnb_opt,
                    
                    # NO TUNE
                    "sgd_FE" : sgd_FE,
                    "dt_FE" : dt_FE, 
                    "ensemble" : rf_n
                    
                    # 1 GRAM CV PREDICTS 
                    
                    # "xgb_CV1" : xgb_CV1, 
                    # "ada_CV1" : ada_CV1, 
                    # "sgd_CV1" : sgd_CV1,
                    # "lr_CV1" : lr_CV1, 
                    # "rf_CV1" : rf_CV1,  
                    # "svm_CV1" : svm_CV1, 
                    # "dt_CV1" : dt_CV1, 
                    # "mnb_CV1" : mnb_CV1
                    
                    # 2 GRAM CV PREDICTS
                    
                    # "xgb_CV2" : xgb_CV2, 
                    # "ada_CV2" : ada_CV2, 
                    # "sgd_CV2" : sgd_CV2,
                    # "lr_CV2" : lr_CV2, 
                    # "rf_CV2" : rf_CV2,  
                    # "svm_CV2" : svm_CV2, 
                    # "dt_CV2" : dt_CV2, 
                    # "mnb_CV2" : mnb_CV2 
                    # 3 GRAM CV PREDICTS
                    
                    # 1 GRAM TF-IDF PREDICTS 
                     
                    # "xgb_TF1" : xgb_TF1, 
                    # "ada_TF1" : ada_TF1, 
                    # "sgd_TF1" : sgd_TF1,
                    # "lr_TF1" : lr_TF1, 
                    # "rf_TF1" : rf_TF1,  
                    # "svm_TF1" : svm_TF1, 
                    # "dt_TF1" : dt_TF1, 
                    # "mnb_TF1" : mnb_TF1
                    
                    # 2 GRAM TF-IDF PREDICTS
                    
                    # "xgb_TF2" : xgb_TF2, 
                    # "ada_TF2" : ada_TF2, 
                    # "sgd_TF2" : sgd_TF2,
                    # "lr_TF2" : lr_TF2, 
                    # "rf_TF2" : rf_TF2,  
                    # "svm_TF2" : svm_TF2, 
                    # "dt_TF2" : dt_TF2, 
                    # "mnb_TF2" : mnb_TF2  
                    
                    # 3 GRAM TF-IDF PREDICTS  
                }
                
                return render(request, "google_square.html" ,context)
        else : 
            messages.MessageFailure(request, 'Subscription Unsuccessful')
            return render ( request , 'google_square.html')
    else : 
        return render ( request , 'google_square.html')
    

# def change_background_color(request):
#     color = request.POST.get('color')
#     # you could save the input to a model BackgroundColor as an instance or update a current record.
#     # creating an instance
#     BackgroundColor.objects.create(bg_color=color)
#     return JsonResponse({'response': 'successfully changed color'})


# def result(request) : 
#     lr_model = pickle.load("lr_model.pkl")
#     mnb_model = pickle.load("mnb_model.pkl")
    
#     payload = [] 
#     payload.append(request.GET['url'])
#     print(payload) 
    
#     lr = lr_model.predict([payload]) 
#     mnb = mnb_model.predict([payload]) 
    
#     return render(request, "index.html" , {'lr':lr , 'mnb': mnb})
    
    # load a .pkl file 
    # 
    
    
    
# PROBLEM STATEMENT 

# OUR SOLUTION 

# VISION USING VERSION 
    # FIRE WALLS - TYPES OF FIREWALLS 

# WORK FLOW 
# TECHNOLOGY
# SIMILIAR PROJECTS 
# ADDITIONS  

# UI PORTRAY 

# MACHINE LEARNING MODELS ARCHITECTURE 
#     DATA SETS - TYPES OF PAYLOADS 
#     MODELS USED 
#     OPTIMIZATION TECHNIQUES 
#         NORMAL MODEL
#         ENSEMBLED MODEL
#     PREDICTION  
    
    
# PS 
# APPROACH 
# UNIQUENESS
# TECHNOLOGIES 
# USER INTERFACE 
# ADD ONS 


# WHY HAVE YOU SELECTED THESE MODELS 
# WHAT ARE THOSE MODELS - EXPLANATION 
# TECHNICAL TERMS
#     FPR 
#     TPR 
#     ACCURACY 
#     PRECISION 
#     RECALL 
#     F1 SCORE 
# OPTIMIZATION 
# WHY 
# USE 
#     HYPER PLANES 
#     ROC CURVE POINT 
#     PR CURVE POINT 
    
# ENSEMBLING 
    