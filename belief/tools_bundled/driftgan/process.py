"""
File contains all the base logic for executing the notebook
"""
import torch
import numpy as np
from classes import Generator, Discriminator
from torch import nn
from torch.autograd import Variable
from skmultiflow.trees import HoeffdingTreeClassifier
from torch.optim import Adadelta
from torch.utils.data import DataLoader

global seq_len


def collate(batch):
    """
    Function for collating the batch to be used by the data loader. This function does not handle labels
    :param batch:
    :return:
    """
    # Stack each tensor variable
    x = torch.stack([torch.tensor(x[:-1]) for x in batch])
    y = torch.Tensor([x[-1] for x in batch]).to(torch.long)
    # Return features and labels
    return x, y


def collate_generator(batch):
    """
    Function for collating the batch to be used by the data loader. This function does handle labels
    :param batch:
    :return:
    """
    global seq_len
    # Stack each tensor variable
    feature_length = int(len(batch[0]) / (seq_len + 1))
    # The last feature length corresponds to the feature we want to predict and
    # the last value is the label of the drift class
    x = torch.stack([torch.Tensor(np.reshape(x[:-feature_length-1], newshape=(seq_len, feature_length)))
                     for x in batch])
    y = torch.stack([torch.tensor(x[-feature_length-1:-1]) for x in batch])
    labels = torch.stack([torch.tensor(x[-1]) for x in batch])
    # Return features and targets
    return x.to(torch.double), y, labels


def fit_and_predict(clf, features, labels, classes):
    predicted = np.empty(shape=len(labels))
    predicted[0] = clf.predict([features[0]])
    clf.reset()
    clf.partial_fit([features[0]], [labels[0]], classes=classes)
    for idx in range(1, len(labels)):
        predicted[idx] = clf.predict([features[idx]])
        clf.partial_fit([features[idx]], [labels[idx]], classes=classes)

    return predicted, clf


def predict_and_partial_fit(clf, features, labels, classes):
    predicted = np.empty(shape=len(labels))
    for idx in range(0, len(labels)):
        predicted[idx] = clf.predict([features[idx]])
        clf.partial_fit([features[idx]], [labels[idx]], classes=classes)

    return predicted, clf


def create_training_dataset(dataset, indices, drift_labels):

    # If there is a periodicity, we switch all previous drifts to the same label
    modified_drift_labels = [x for x in drift_labels]
    if drift_labels[-1] != 0:
        modified_drift_labels = []
        for label in drift_labels:
            if label == drift_labels[-1]:
                modified_drift_labels.append(0)  # The current label
            elif label > drift_labels[-1]:
                modified_drift_labels.append(label-1)  # Decrease all labels that are greater than this
            else:
                modified_drift_labels.append(label)

    training_dataset = np.hstack((dataset[indices[0][0]:indices[0][1]],
                                  np.ones((indices[0][1]-indices[0][0], 1)) * modified_drift_labels[0]))
    for idx in range(1, len(modified_drift_labels)):
        training_dataset = np.vstack((training_dataset, np.hstack((dataset[indices[idx][0]:indices[idx][1]],
                                      np.ones((indices[idx][1]-indices[idx][0], 1)) * modified_drift_labels[idx]))))

    return training_dataset


def train_discriminator(real_data, fake_data, discriminator, generator, optimizer, loss_fn,
                        generator_labels, device):
    # for idx in range(steps):
    for features, labels in real_data:
        # Set the gradients as zero
        discriminator.zero_grad()
        optimizer.zero_grad()

        # Get the loss when the real data is compared to ones
        features = features.to(device).to(torch.float)
        labels = labels.to(device)
        # features = features.to(torch.float)

        # Get the output for the real features
        output_discriminator = discriminator(features)

        # The real data is without any concept drift. Evaluate loss against zeros
        real_data_loss = loss_fn(output_discriminator, labels)

        # Get the output from the generator for the generated data compared to ones which is drifted data
        generator_input = None
        for input_sequence, _, _ in fake_data:
            generator_input = input_sequence.to(device).to(torch.float)
            break
        generated_output = generator(generator_input)  # .double().to(device))

        generated_output_discriminator = discriminator(generated_output)

        # Here instead of ones it should be the label of the drift category
        generated_data_loss = loss_fn(generated_output_discriminator, generator_labels)

        # Add the loss and compute back prop
        total_iter_loss = generated_data_loss + real_data_loss
        total_iter_loss.backward()

        # Update parameters
        optimizer.step()

    return discriminator


def train_generator(data_loader, discriminator, generator, optimizer, loss_fn, loss_mse, steps, device):
    epoch_loss = 0
    for idx in range(steps):

        optimizer.zero_grad()
        generator.zero_grad()

        generated_input = target = labels = None
        for generator_input, target, l in data_loader:
            generated_input = generator_input.to(torch.float).to(device)
            target = target.to(torch.float).to(device)
            labels = l.to(torch.long).to(device)
            break

        # Generating data for input to generator
        generated_output = generator(generated_input)

        # Compute loss based on whether discriminator can discriminate real data from generated data
        generated_training_discriminator_output = discriminator(generated_output)

        # Compute loss based on ideal target values
        loss_generated = loss_fn(generated_training_discriminator_output, labels)

        loss_lstm = loss_mse(generated_output, target)

        total_generator_loss = loss_generated + loss_lstm

        # Back prop and parameter update
        total_generator_loss.backward()
        optimizer.step()
        epoch_loss += total_generator_loss.item()

    return generator


def equalize_classes(features, max_count=100):
    modified_dataset = None

    labels = features[:, -1]
    unique_labels, counts = np.unique(labels, return_counts=True)
    min_count = min(min(counts), max_count)

    if min_count == max(counts) == max_count:
        return features

    for label, count in zip(unique_labels, counts):
        indices = np.where(features[:, -1] == label)[0]
        chosen_indices = np.random.choice(indices, min_count)
        if modified_dataset is None:
            modified_dataset = features[chosen_indices, :]
            continue
        modified_dataset = np.vstack((modified_dataset, features[chosen_indices, :]))
    return modified_dataset


def concatenate_features(data, sequence_len=2, has_label=True):
    if has_label is True:
        modified_data = data[:, :-1]
    else:
        modified_data = data

    idx = sequence_len
    modified_data = np.vstack((np.zeros((sequence_len - 1, len(modified_data[idx]))), modified_data))
    output = np.hstack((modified_data[idx - sequence_len:idx + 1, :].flatten(), data[idx-sequence_len][-1]))
    idx += 1
    while idx < len(modified_data)-1:
        output = np.vstack((output, np.hstack((modified_data[idx - sequence_len:idx + 1, :].flatten(),
                                               data[idx-sequence_len][-1]))))
        idx += 1

    # The last value
    output = np.vstack((output, np.hstack((modified_data[idx - sequence_len:, :].flatten(), data[-1][-1]))))
    output = np.vstack((output, np.hstack((modified_data[idx - sequence_len:idx, :].flatten(),
                                           modified_data[sequence_len - 1],
                                           data[0][-1]))))
    return output


def train_gan(features, device, discriminator, generator, epochs=100, steps_generator=100, weight_decay=0.0005,
              max_label=1, generator_batch_size=1, seed=0, batch_size=8, lr=0.001, equalize=True,
              sequence_length=2):

    # Set the seed for torch and numpy
    torch.manual_seed(seed=seed)
    torch.cuda.manual_seed(seed=seed)
    torch.cuda.manual_seed_all(seed=seed)
    np.random.seed(seed)

    # Losses for the generator and discriminator
    loss_mse_generator = nn.MSELoss()
    loss_generator = nn.CrossEntropyLoss()
    loss_discriminator = nn.CrossEntropyLoss()

    # Create the optimizers for the models
    optimizer_generator = Adadelta(generator.parameters(), lr=lr, weight_decay=weight_decay)
    optimizer_discriminator = Adadelta(discriminator.parameters(), lr=lr, weight_decay=weight_decay)

    # Label vectors
    ones = Variable(torch.ones(generator_batch_size)).to(torch.long).to(device)

    # This data contains the current vector and next vector
    concatenated_data = concatenate_features(features, sequence_len=sequence_length)

    if equalize:
        features = equalize_classes(features)
        concatenated_data = equalize_classes(concatenated_data)

    # Define the data loader for training
    real_data = DataLoader(features, batch_size=batch_size, shuffle=True, collate_fn=collate)
    generator_data = DataLoader(concatenated_data, batch_size=generator_batch_size, shuffle=False,
                                collate_fn=collate_generator)

    # This is the label for new drifts (any input other than the currently learned distributions)
    generator_label = ones * max_label

    for epochs_trained in range(epochs):
        discriminator = train_discriminator(real_data=real_data, fake_data=generator_data, discriminator=discriminator,
                                            generator=generator, optimizer=optimizer_discriminator,
                                            loss_fn=loss_discriminator, generator_labels=generator_label, device=device)

        generator = train_generator(data_loader=generator_data, discriminator=discriminator, generator=generator,
                                    optimizer=optimizer_generator, loss_fn=loss_generator, loss_mse=loss_mse_generator,
                                    steps=steps_generator, device=device)
    return generator, discriminator


def process_data(features, labels, training_features, device, epochs=100, steps_generator=100, equalize=True,
                 test_batch_size=4, seed=0, batch_size=8, lr=0.001, weight_decay=0.0005, training_window_size=100,
                 generator_batch_size=1, sequence_length=2, repeat_factor=4):
    global seq_len
    seq_len = sequence_length

    # Set the seed
    import random

    random.seed(seed)
    torch.manual_seed(seed=seed)
    torch.cuda.manual_seed(seed=seed)
    torch.cuda.manual_seed_all(seed=seed)
    np.random.seed(seed)
    # torch.backends.cudnn.deterministic = True
    # torch.backends.cudnn.benchmark = False
    # torch.set_deterministic(True)

    current_batch_size = batch_size

    y_pred = []
    y_true = []
    clf = HoeffdingTreeClassifier()

    classes = np.unique(labels)
    x = training_features[:training_window_size, :]
    y = labels[:training_window_size]

    drifts_detected = []
    generator_label = 1

    # Create the Generator and Discriminator objects
    generator = Generator(inp=features.shape[1], out=features.shape[1], sequence_length=sequence_length)
    discriminator = Discriminator(inp=features.shape[1], final_layer_incoming_connections=512)

    generator.move(device=device)

    # Set the models to the device
    generator = generator.to(device=device)
    discriminator = discriminator.to(device=device)

    drift_indices = [(0, training_window_size)]  # Initial training window
    drift_labels = []

    temp_label = [0]

    initial_epochs = epochs * 2

    predicted, clf = fit_and_predict(clf=clf, features=x, labels=y, classes=classes)
    y_pred = y_pred + predicted.tolist()
    y_true = y_true + y

    # Create training dataset
    training_dataset = create_training_dataset(dataset=features, indices=drift_indices, drift_labels=[0])

    generator, discriminator = train_gan(features=training_dataset, device=device, discriminator=discriminator,
                                         generator=generator, epochs=initial_epochs, steps_generator=steps_generator,
                                         seed=seed, batch_size=batch_size, lr=lr, equalize=equalize,
                                         max_label=generator_label, generator_batch_size=generator_batch_size,
                                         weight_decay=weight_decay, sequence_length=sequence_length)

    index = training_window_size

    generator.eval()
    discriminator.eval()

    while index + training_window_size < len(features):

        data = features[index:index + test_batch_size]
        data_labels = labels[index:index + test_batch_size]
        result = discriminator(torch.Tensor(data).to(torch.float).to(device))
        prob, max_idx = torch.max(result, dim=1)
        max_idx = max_idx.cpu().detach().numpy()
        if np.any(max_idx != max_idx[0]) or max_idx[0] == 0:
            predicted, clf = predict_and_partial_fit(clf=clf, features=training_features[index:index + test_batch_size],
                                                     labels=data_labels,
                                                     classes=classes)
            y_pred = y_pred + predicted.tolist()
            y_true = y_true + data_labels
            index += test_batch_size
            continue

        max_idx = max_idx[0]
        # Drift detected
        drift_indices.append((index, index+training_window_size))

        if temp_label[0] != 0:
            drift_labels.append(temp_label[0])  # add the index of the previous drift if it was a recurring drift

        else:
            drift_labels.append(generator_label)

        if max_idx != generator_label:
            # Increase the max_idx by 1 if it is above the previous drift
            if temp_label[0] <= max_idx and temp_label[0] != 0:
                max_idx += 1
            temp_label = [max_idx]
            # We reset the top layer predictions because the drift order has changed and the network should be retrained
            discriminator.reset_top_layer()
            discriminator = discriminator.to(device)
            # print('Previous drift %d occurred at index %d.' % (max_idx, index))

        else:
            # If this is a new drift, label for the previous drift training dataset is the previous highest label
            # which is the generator label
            temp_label = [0]
            discriminator.update()
            discriminator = discriminator.to(device)
            generator_label += 1

        generator = Generator(inp=features.shape[1], out=features.shape[1], sequence_length=sequence_length)
        generator = generator.to(device=device)

        generator.train()
        discriminator.train()

        training_dataset = create_training_dataset(dataset=features,
                                                   indices=drift_indices,
                                                   drift_labels=drift_labels+temp_label)

        generator, discriminator = train_gan(features=training_dataset, device=device,
                                             discriminator=discriminator,
                                             generator=generator, epochs=epochs,
                                             steps_generator=steps_generator, seed=seed,
                                             batch_size=current_batch_size, max_label=generator_label,
                                             lr=lr, equalize=equalize, weight_decay=weight_decay,
                                             sequence_length=sequence_length)

        # Set the generator and discriminator to evaluation mode
        generator.eval()
        discriminator.eval()

        # Set the indices for the training window
        training_idx_start = index
        training_idx_end = training_idx_start + training_window_size

        # If a previous drift has occurred use those for training the classifier but not predict on them
        if temp_label[0] != 0:
            clf.reset()
            for indices, label in zip(drift_indices[:-1], drift_labels):
                if label == temp_label[0]:
                    rows = training_features[indices[0]:indices[1], :]
                    targets = labels[indices[0]:indices[1]]
                    # Randomly sample .1 of the data
                    len_indices = list(range(0, rows.shape[0]))
                    chosen_indices = random.sample(len_indices, int(rows.shape[0] / repeat_factor))
                    # Append rows and targets. Do random.sample and then split the matrix
                    rows = rows[chosen_indices]
                    targets = [targets[x] for x in chosen_indices]
                    clf.partial_fit(X=rows, y=targets, classes=classes)

            predicted, clf = predict_and_partial_fit(clf=clf,
                                                     features=training_features[training_idx_start:training_idx_end, :],
                                                     labels=labels[training_idx_start:training_idx_end],
                                                     classes=classes)

        else:
            predicted, clf = fit_and_predict(clf=clf,
                                             features=training_features[training_idx_start:training_idx_end, :],
                                             labels=labels[training_idx_start:training_idx_end],
                                             classes=classes)

        # Add the predicted and true values to the list
        predicted = predicted.tolist()
        y_pred = y_pred + predicted
        y_true = y_true + labels[training_idx_start:training_idx_end]

        drifts_detected.append(index)

        print(index)
        index += training_window_size

    # Test on the remaining features
    features_window = training_features[index:, :]
    labels_window = labels[index:]
    y_hat, clf = predict_and_partial_fit(clf, features=features_window, labels=labels_window, classes=classes)
    y_pred = y_pred + y_hat.tolist()
    y_true = y_true + labels_window

    return y_pred, y_true, drifts_detected
